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

Status: **design complete, implementation in progress.** See
[`docs/design.md`](docs/design.md) for the design and
[`docs/plans/`](docs/plans/) for the implementation plan.

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
systemctl --user daemon-reload
systemctl --user enable --now secretsd.socket
```

Enable the **socket**, not the service. The first client connection to
`$XDG_RUNTIME_DIR/secretsd.sock` causes systemd to spawn the daemon. Before
starting it, create the deployment-owned drop-in described in
[`docs/dotfiles-cutover.md`](docs/dotfiles-cutover.md); it supplies the human
secret directory and the real helper-binary paths for that machine.

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
