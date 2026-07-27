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
