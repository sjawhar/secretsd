# Dotfiles cutover contract

This package owns generic user units. The consuming dotfiles own every
machine-specific secret-store path and hardware connection in a systemd
drop-in.

## Deployment drop-in

Create `~/.config/systemd/user/secretsd.service.d/deployment.conf` on each
target machine. This example deliberately uses literal absolute paths:

```ini
# ~/.config/systemd/user/secretsd.service.d/deployment.conf
[Service]
Environment=SECRETSD_HUMAN_DIR=/home/alice/.config/secretsd/secrets.human.d
Environment=SECRETSD_SOPS_BIN=/home/alice/.local/share/mise/installs/sops/3.10.2/sops
Environment=PCSCLITE_CSOCK_NAME=/run/user/1000/pcscd.comm
Environment=PATH=/home/alice/.local/bin:/home/alice/.local/share/mise/installs/age-plugin-yubikey/0.5.0:/usr/local/bin:/usr/bin
```

Replace every example path with the path on that machine before starting the
service. `SECRETSD_HUMAN_DIR` is mandatory: the daemon refuses to start if it
is absent or empty, preventing an accidental fallback to another user's
secret directory. All deployment values must be absolute: systemd does not run
an interactive shell for user services, so `~`, `$HOME`, command
substitutions, and version placeholders are not deployment configuration. On
a machine with a directly attached YubiKey, omit `PCSCLITE_CSOCK_NAME`; on a
headless devbox, set it to the absolute path of the pcscd bridge socket.

`SECRETSD_SOPS_BIN` must name the real `sops` executable, not a mise shim.
Likewise, `PATH` must include the absolute directory holding the real
`age-plugin-yubikey` executable. A systemd user service starts with a minimal
PATH, and a mise shim re-executes `mise`; neither assumption is safe for the
daemon. Use `mise which sops` to obtain the resolved executable path and
`mise bin-paths age-plugin-yubikey` to identify the real plugin directory, then
write those absolute results into the drop-in.

## Memlock policy

`SECRETSD_MEMLOCK` is daemon-side startup configuration only; clients cannot
select it. It accepts `require` (the default) or `optional`. The packaged unit
uses `LimitMEMLOCK=infinity`, which is the ideal production setting. `require`
also accepts a finite soft and hard limit of at least 512 MiB, enough for the
bounded worker pool plus substantial allocation headroom, but no finite limit
can guarantee every future `MCL_FUTURE` allocation remains lockable.

Use `SECRETSD_MEMLOCK=optional` only for local development, tests, or a
hardware-free harness. It logs a warning and continues if memory locking is
unavailable, so plaintext pages may be swappable. Do not put it in a production
deployment drop-in.

After creating or changing the drop-in, reload and restart the daemon:

```bash
systemctl --user daemon-reload
systemctl --user restart secretsd.service
```

Do not rely on `systemctl --user set-environment` for this configuration. It
does not update an already-running daemon. The restart above removes all
memory-only grants, including grants made before an upgrade or a drop-in
change; the next human-tier request requires a fresh YubiKey touch.

## Socket activation

Install the packaged units and enable the **socket**, never the service:

```bash
systemctl --user enable --now secretsd.socket
```

`secretsd.socket` listens at `%t/secretsd.sock` (`%t` is
`XDG_RUNTIME_DIR`). On the first client connection, systemd starts
`secretsd.service` and passes it the listening socket. The packaged service
uses an absolute release-owned executable path, `%h/.local/bin/secrets serve`; its
child `PATH` is only for `sops` and `age-plugin-yubikey` and never resolves
`ExecStart`.

## Release archive layout

Each Linux release archive has one top-level `secretsd-<tag>-linux-x86_64/`
directory with this installation layout:

```
bin/secrets
share/secretsd/opencode/plugins/secretsd.ts
systemd/secretsd.service
systemd/secretsd.socket
```

Install `bin/secrets` as executable `~/.local/bin/secrets`, install the plugin at
`~/.local/share/secretsd/opencode/plugins/secretsd.ts`, and install both unit
files for the user service manager. The plugin has no release-local imports;
the OpenCode loader supplies `@opencode-ai/plugin`.

## Consuming-dotfiles changes

The consuming dotfiles must:

1. Pin the released `secretsd` version in `mise.toml` and install the archive
   layout so it exposes `~/.local/bin/secrets` and
   `~/.local/share/secretsd/opencode/plugins/secretsd.ts`.
2. Point the OpenCode plugin entry at
   `file://{env:HOME}/.local/share/secretsd/opencode/plugins/secretsd.ts`.
3. Install the packaged units, create the machine's deployment drop-in, and
   enable `secretsd.socket`.
4. Remove `shims/secrets`, `shims/tests/test_secrets_shim.py`, the moved plugin,
   and `opencode/plugins/secretsd.test.ts` only after the checks below pass.

The headless devbox follows the same direct hardware-touch flow for an
agent-initiated human-tier grant as the laptop. It requires no desktop session
or separate approval service.

## Required cutover order

Before removing the bash shim, install the Rust release and run its full test
suite on both the laptop and devbox. Then, on **every** target machine, verify
the Rust `secrets` client through non-interactive SSH with an otherwise empty
environment and no daemon runtime socket:

```bash
ssh "$host" 'env -i PATH="$PATH" HOME="$HOME" DOTFILES_DIR="$HOME/.dotfiles" secrets get ANTHROPIC_API_KEY >/dev/null && test ! -S "/run/user/$(id -u)/secretsd.sock"'
```

This check intentionally omits `XDG_RUNTIME_DIR`. Agent-tier access must not
assume it exists or make a top-level shell expansion mandatory under `set -u`;
such a failure can take down unrelated non-interactive infrastructure. Only
after this command succeeds on both machines may the bash shim be removed.
Then install the plugin path, reload user systemd, and verify agent-tier
consumers—including Legion, Dojo, and skill MCPs—before enabling human-tier
requests.
