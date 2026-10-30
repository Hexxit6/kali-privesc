# PoC
This chain assumes a stock Kali installation with:

- `lightdm 1.33.1-4` running as root under systemd
- the stock `lightdm-gtk-greeter`
- the stock D-Bus policy that allows `AddLocalXSeat` to local users
- `/var/lib/lightdm` owned by `lightdm`, and `/usr/local/bin` root-owned
- a normal local user shell

It does **not** start, stop, or reconfigure LightDM, and it does **not** use the
lab's `start-default-seat=false` setting. The current user is detected
automatically; no `attacker` account is assumed.


## Usage
Run as the normal local user, not root:

```sh
cd poc
./poc.sh --check
```

`--check` is read-only. It verifies the running daemon, D-Bus name, paths,
permissions, Xvfb, and the prebuilt binaries or compiler.

After authorization:

```sh
./poc.sh --run
```

Expected result:

```text
uid=0(root) gid=0(root) groups=0(root)
uid=1000(USER) gid=1000(USER) euid=0(root) groups=1000(USER)
```

The fake session child writes:

- `/var/tmp/poc-root-<uid>` — root `id` output;
- `/etc/sudoers.d/poc-<uid>` — a `NOPASSWD` entry for the invoking user;
- `/var/tmp/poc-rootsh-<uid>` — a setuid fallback restricted to the user's
  primary group.

The runner stops its private Xvfb/XSETTINGS helpers on exit, but the root
artifacts remain until cleanup.

## Cleanup

On a default Kali host, `/usr/local/bin` and the shared-data directory are
changed. Restore them with:

```sh
sudo ./cleanup.sh
```

Cleanup removes only `/usr/local/bin/lightdm` carrying the `# POC` marker,
restores `/usr/local/bin` to `root:root 0755`, restores
`/var/lib/lightdm/data` from the backup if needed, and removes the sudoers
entry, root shell, evidence, state, and work directory.


## Files

| File | Purpose |
|---|---|
| `poc.sh` | Preflight, Xvfb, XSETTINGS manager, D-Bus trigger, verification |
| `libpwn.c` | Greeter module: symlink pivot, `ENSURE_SHARED_DIR`, fake `lightdm` |
| `xsettings_pwn.c` | Minimal XSETTINGS manager publishing `Gtk/Modules` |
| `cleanup.sh` | Root cleanup |
| `bin/libpwn.so` | Prebuilt x86_64 module (compiled fallback available) |
| `bin/xsettings_pwn` | Prebuilt x86_64 XSETTINGS manager |


## Notes and limits

- Requires x86_64 for the prebuilt binaries. On another architecture, or to
  force a source build, install `gcc` and `libx11-dev`, then run with
  `POC_FORCE_BUILD=1 ./poc.sh --run`.
- The module reads `/var/tmp/lightdm-poc.state` written by `poc.sh`; it uses
  the invoking username only for the sudoers line.
- The chain depends on Debian's `06_change-user-dirs.patch` and the GTK3
  greeter. It is not an upstream-generic LightDM 1.33.1 chain.
- The GTK `Gtk/Modules` primitive is already known prior art (CVE-2026-76023).
- Do not run `--run` on a host you do not own or have not been authorized to
  test.
- Do not run the privesc if you don't feel comfortable in you capability of
  reverting the system to it's initial state.
