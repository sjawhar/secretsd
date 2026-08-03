# src/client

The client half of the `secrets` binary. Reached from `src/bin/secrets.rs` for
any argv that is not `serve`.

## Tier split

`Context::value` forks on one fact: does the key appear in the configured
source roots' `secrets.human.d/` directories?

- **Agent tier** — decrypted here, in-process, by shelling out to sops. The
  daemon is never contacted, no grant exists, no touch happens.
- **Human tier** — brokered. `HumanClient` speaks the socket protocol and blocks
  until the daemon reaches a terminal response.

A key present in both tiers is a hard error (`AmbiguousKey`), never a silent
preference for one.

| File | Owns |
|---|---|
| `cli.rs` | argv dispatch, the `get`/`list`/`edit`/inject surface |
| `../config.rs` | source-root loading and agent-file precedence shared with the daemon |
| `agent.rs` | local sops decryption of `secrets.env` |
| `human.rs` | broker transport; builds the scoped frame for `GET`/`REQUEST` |
| `response.rs` | parsing broker replies, including exact-length payloads |
| `error.rs` | `CliError` and the agent-facing guidance strings |
| `status.rs` | `get` flag parsing and the JSON status line |

## The `get` contract

Three different operations behind one subcommand — do not collapse them:

| Form | Sends | Prints |
|---|---|---|
| `get KEY` | `REQUEST` | JSON status; pre-authorizes, so it may prompt for a touch |
| `get KEY --value` | `GET` | the secret bytes plus one newline |
| `get KEY --no-request` | `GRANTS` | JSON status only; never prompts |

Bare `get` deliberately does **not** print the value: an agent that runs it and
reads the JSON as the secret will report a working key as a placeholder. The
status path must never send `GET`, or a status check would make the human's key
blink.

## Conventions

Guidance strings for daemon errors start with
`AGENT NOTICE: ask the human; do not retry-loop.` and then say what to do. They
are the only place an agent learns why it was refused, so a new `ErrCode` needs
an arm in both `error.rs` and `response.rs` — the compiler enforces this via
exhaustive matches.

Never render a secret, a token, or any prefix of either into an error. Tests
assert the absence of the token bytes in stderr.
