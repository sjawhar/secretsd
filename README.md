# secretsd

Session-scoped secrets broker with hardware-gated grants.

`secretsd` gives an AI coding agent access to a sensitive secret only after a
human physically approves it with a YubiKey touch — and then keeps that access
available to *that one session* for as long as the session lives, so approval
happens once per session instead of once every few minutes.

- **Presence is proven at grant time**, not continuously. One touch per
  (session, key).
- **Per-session scope.** A grant belongs to the session that asked for it. A
  sibling session in the same process gets its own request, not a free ride.
- **No plaintext at rest.** Values live only in the daemon's locked memory,
  zeroized when the grant dies.
- **Unattended secrets stay unattended.** Keys that agents legitimately need
  overnight never touch this daemon; they keep decrypting with a disk-resident
  key, exactly as before.

See [`docs/design.md`](docs/design.md) for the current architecture.

## Install

Download and extract a release tarball, then install the binary and packaged
user units. Do not link units to a source checkout: the installed configuration
must remain valid after the checkout or extracted release directory is gone.

```bash
tar xzf secretsd-vX.Y.Z-linux-x86_64.tar.gz
cd secretsd-vX.Y.Z-linux-x86_64
install -Dm755 bin/secrets "$HOME/.local/bin/secrets"
install -Dm644 systemd/secretsd.socket "$HOME/.config/systemd/user/secretsd.socket"
install -Dm644 systemd/secretsd.service "$HOME/.config/systemd/user/secretsd.service"
install -Dm644 share/secretsd/opencode/plugins/secretsd.ts \
    "$HOME/.local/share/secretsd/opencode/plugins/secretsd.ts"
install -Dm644 share/secretsd/skills/using-secrets/SKILL.md \
    "$HOME/.local/share/secretsd/skills/using-secrets/SKILL.md"
systemctl --user daemon-reload
systemctl --user enable --now secretsd.socket
```

The plugin speaks a versioned wire protocol to the daemon, so the two must
come from the same release: install the packaged plugin (or, if OpenCode
loads it from a git pin such as
`secretsd@git+https://github.com/sjawhar/secretsd.git#vX.Y.Z`, update that
tag to the installed version) and restart OpenCode after upgrading the
daemon. A stale plugin fails loudly at the version handshake.

Enable the **socket**, not the service. The first client connection to
`$XDG_RUNTIME_DIR/secretsd.sock` causes systemd to spawn the daemon. Before
starting it, declare the source roots in `~/.config/secretsd/config.toml`:

```toml
[source.dotfiles]
path = "~/.dotfiles"

[source.private]
path = "~/src/secrets-private"
```

Each root may contain `secrets.env`, `secrets.local.env`, and
`secrets.human.d/`. Set the daemon's helper-binary and hardware connection
paths in its deployment-owned systemd drop-in.

On a machine you drive over ssh, enable lingering as well:

```bash
loginctl enable-linger "$USER"
```

Without it, `logind` removes `$XDG_RUNTIME_DIR` when your last login ends, taking
the socket, the daemon, every grant, and every session token file with it — even
though a tmux server and the agent sessions inside it keep running. Check it with
`loginctl show-user "$USER" -p Linger`.

Grants exist only in daemon memory. Any daemon restart—including a release
upgrade or a drop-in change—removes every grant and requires a fresh YubiKey
touch before a human-tier secret can be used again.

## Why not an off-the-shelf secrets manager?

Vault/OpenBao + GatePlane, Infisical Access Requests, 1Password, and Teleport
all implement request/approve/expire flows, and all were evaluated. None bind a
grant to an *ephemeral agent session*, and none speak "YubiKey touch" as the
approval primitive. Vault additionally needs an unseal key on disk, which
recreates the plaintext-at-rest problem this exists to avoid. Details in
[`docs/design.md`](docs/design.md).

## License

Apache-2.0 OR MIT.
