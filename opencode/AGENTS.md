# opencode

The OpenCode plugin and the skill that ships with it. TypeScript, run by bun;
`bun run test:secretsd-plugin` from the repo root, and CI gates it.

## Why it lives here

The plugin speaks the versioned wire protocol in `src/proto.rs`. Keeping it in
this repo means a protocol change and its client land in one commit and one
release, and consumers pin a tag rather than a branch.

## What the plugin does

| Hook | Purpose |
|---|---|
| `config` | pushes `../skills` onto `config.skills.paths` — this is how a plugin ships a skill |
| `shell.env` | issues the session token, registers it, exports only `SECRETSD_SESSION_TOKEN_FILE` |
| `event` | on `session.deleted`, unregisters and deletes the token file |
| `tool` | `secrets_request` — asks for a grant, returns status, never a value |
| `dispose` | aborts in-flight requests and cleans up every session |

Registration is driven by `shell.env`, not by a session-created event. The token
file is written to a temp name and renamed, so a reader sees a whole token or no
file. Only the *path* is exported; the token value must never enter an
environment.

`resolveRuntimeDir` picks the directory holding both the socket and the token:
an explicit override, then `XDG_RUNTIME_DIR`, then `/run/user/<uid>`. That last
step mirrors `SocketPath::resolve` in `src/client.rs` and is load-bearing — a
serve process started from a tmux server or non-interactive ssh that never had
`XDG_RUNTIME_DIR` would otherwise issue no token at all, for every session, for
its whole lifetime, while the `secrets` CLI beside it resolved the same socket
fine. The resolved root is verified rather than trusted: it must exist, be a
directory this uid owns, and not be writable by other users, and the token
directory itself must be a real directory, never a symlink — `chmodSync` and
`writeFileSync` both follow links. The runtime root is never created; a missing
`/run/user/<uid>` means there is no systemd user session, and fabricating it
would put tokens where the daemon never looks while reporting success. Each
refusal names the offending path so the agent that hits it can say what to fix.

`resolveSocketPath` picks the broker separately: an explicit override, then
`SECRETSD_SOCK`, then `<runtime>/secretsd.sock`. It honours the same variable as
`BrokerClient::from_environment` on purpose. This plugin mints the token and the
CLI presents it, so if only the CLI followed `SECRETSD_SOCK` the token would be
registered with one daemon and offered to another, and the request would fail
`UNKNOWN_TOKEN` with nothing on either side explaining why.

A cached session state is not proof its token file still exists. `logind` removes
`/run/user/<uid>` when the user's last login ends unless lingering is enabled, so
a serve process inside a long-lived tmux server outlives its own token file, and
the CLI reads that file rather than this plugin's memory. `shell.env` therefore
re-checks and calls `restoreTokenFile`, which rewrites **the same** token:
registering a fresh one for a session displaces the old token and revokes its
grants (`Registry::register`, `src/grants.rs:153`), which would charge the human
another touch to recover from a file the plugin lost.

`secrets_request` sends `REQUEST`, never `GET`. Its result is a status string,
so a tool result can never carry a secret — two tests assert that.

## skills/

`using-secrets/SKILL.md` teaches agents the CLI. It exists because an agent read
the JSON status from `secrets get KEY` as the secret itself and told the human
their key was a 14-character placeholder. It leads with that mistake.

Its description triggers on the symptoms an agent is holding when it goes wrong
(`OPENAI_API_KEY`, `sk-`, `401`, "placeholder"), not on the word "secrets". When
the CLI surface changes, this file changes with it — it documents behaviour that
is verified against the shipped binary, not intentions.

## Size

`secretsd.ts` and `secretsd.test.ts` both carry `// allow: SIZE_OK` with a
reason. One closure owns a session's token, broker lifecycle, and cancellation
state; splitting it would spread that lifetime across files.

Size pressure is not a reason to split the plugin across files. The release
installs exactly one plugin file (`install -m 0644 opencode/plugins/secretsd.ts`
in `.github/workflows/release.yml`) and `package.json` ships only that path, so
a sibling module would resolve in this checkout and in `bun test` while being
absent for every consumer. The archive verification only asserts `secretsd.ts`
exists, so it would not catch it either: the plugin must import nothing relative.
