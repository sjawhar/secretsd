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
- **Announced hardware interaction.** The key never blinks without a
  notification first, naming the key and request.
- **Unattended secrets stay unattended.** Keys that agents legitimately need
  overnight never touch this daemon; they keep decrypting with a disk-resident
  key, exactly as before.

Status: **design complete, implementation in progress.** See
[`docs/design.md`](docs/design.md) for the design and
[`docs/plans/`](docs/plans/) for the implementation plan.

## Install

Download and extract a release tarball, then install the binary and link the
user units:

```bash
tar xzf secretsd-vX.Y.Z-linux-x86_64.tar.gz
cd secretsd-vX.Y.Z-linux-x86_64
install -Dm755 secretsd ~/.dotfiles/bin/secretsd
mkdir -p ~/.config/systemd/user
ln -sf "$PWD/systemd/secretsd.socket" ~/.config/systemd/user/secretsd.socket
ln -sf "$PWD/systemd/secretsd.service" ~/.config/systemd/user/secretsd.service
systemctl --user daemon-reload
systemctl --user enable --now secretsd.socket
```

## Why not an off-the-shelf secrets manager?

Vault/OpenBao + GatePlane, Infisical Access Requests, 1Password, and Teleport
all implement request/approve/expire flows, and all were evaluated. None bind a
grant to an *ephemeral agent session*, and none speak "YubiKey touch" as the
approval primitive. Vault additionally needs an unseal key on disk, which
recreates the plaintext-at-rest problem this exists to avoid. Details in
[`docs/design.md`](docs/design.md).

## License

Apache-2.0 OR MIT.
