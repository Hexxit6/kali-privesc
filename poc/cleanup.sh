#!/usr/bin/env bash
# Remove poc artifacts and restore the two stock Kali directory properties
# that the exploit changes. Run as root or via `sudo ./cleanup.sh`.

set -Eeuo pipefail

STATE="/var/tmp/lightdm-poc.state"
DATA="/var/lib/lightdm/data"
BACKUP="/var/lib/lightdm/data.poc-backup"
FAKE="/usr/local/bin/lightdm"

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n bash "$0" "$@"
    fi
    echo "cleanup: run as root or ensure sudo -n works" >&2
    exit 1
fi

TARGET_UID="${SUDO_UID:-}"
if [ -z "$TARGET_UID" ] && [ -r "$STATE" ]; then
    TARGET_UID="$(awk -F= '$1 == "UID" { print $2; exit }' "$STATE")"
fi
if [ -z "${TARGET_UID:-}" ]; then
    echo "cleanup: cannot determine target uid; pass it as \$1" >&2
    exit 1
fi
case "$TARGET_UID" in
    ''|*[!0-9]*) echo "cleanup: invalid uid: $TARGET_UID" >&2; exit 1 ;;
esac

WORK="/var/tmp/lightdm-poc-${TARGET_UID}"
ROOTSH="/var/tmp/poc-rootsh-${TARGET_UID}"
EVIDENCE="/var/tmp/poc-root-${TARGET_UID}"
SUDOERS="/etc/sudoers.d/poc-${TARGET_UID}"

echo "cleanup: target uid $TARGET_UID"

# Remove the planted binary only if it carries the poc marker.
if [ -f "$FAKE" ] && [ ! -L "$FAKE" ]; then
    if grep -q '^# POC2$' "$FAKE" 2>/dev/null; then
        rm -f -- "$FAKE"
        echo "cleanup: removed $FAKE"
    else
        echo "cleanup: WARNING: $FAKE exists but is not marked POC2; not removing" >&2
    fi
elif [ -L "$FAKE" ]; then
    echo "cleanup: WARNING: $FAKE is a symlink; not removing" >&2
fi

# The root chown changed /usr/local/bin to bin:lightdm 0770. Restore the stock
# Kali ownership/mode, but only if the directory currently looks like ours.
if [ "$(stat -c '%U:%G' /usr/local/bin 2>/dev/null)" = "bin:lightdm" ]; then
    chown root:root /usr/local/bin
    chmod 0755 /usr/local/bin
    echo "cleanup: restored /usr/local/bin to root:root 0755"
fi

# Restore the shared-data directory if the module did not already do it.
if [ -L "$DATA" ]; then
    rm -f -- "$DATA"
    echo "cleanup: removed dangling data symlink"
fi
if [ -d "$BACKUP" ] && [ ! -e "$DATA" ]; then
    mv -- "$BACKUP" "$DATA"
    echo "cleanup: restored $DATA"
elif [ -e "$BACKUP" ]; then
    echo "cleanup: WARNING: $BACKUP remains; inspect it before deleting" >&2
fi

# Remove quick win setuid
chmod 755 /bin/bash

rm -f -- "$SUDOERS" "$ROOTSH" "$EVIDENCE" "$STATE" \
         /tmp/lightdm-poc.log /tmp/poc.dbus
if [ -L "$WORK" ]; then
    echo "cleanup: WARNING: $WORK is a symlink; not removing" >&2
else
    rm -rf -- "$WORK"
fi
echo "cleanup: removed per-user artifacts"

echo "cleanup: done"
