---
name: using-secrets
description: "Use BEFORE running any command that needs an API key, token, password, or credential, and whenever a secret looks missing, wrong, truncated, or like a placeholder. This machine has no secrets in the environment — every key comes from the `secrets` CLI, and `secrets get KEY` does NOT print the value. Triggers on: secrets get, secrets list, API key, API token, access token, credential, OPENAI_API_KEY, ANTHROPIC_API_KEY, AIRTABLE_TOKEN, SLACK_MCP_XOXP_TOKEN, GROQ_API_KEY, DEEL_API_KEY, sk-, xoxp-, export KEY=, env var for a command, 'key is a placeholder', 'key looks wrong', 'invalid api key', 401, 403, authentication failed, sops, YubiKey touch, secretsd, secrets_request, SecretsRequest, grant expired, key blinking, TIMEOUT, TOO_MANY_PENDING."
---

# Using `secrets` and the `secrets_request` tool

Every credential on this machine comes from `secrets` (CLI) or `secrets_request` (the MCP
tool, shown as `SecretsRequest` in OpenCode). Nothing is pre-exported into the environment,
so a bare `echo $OPENAI_API_KEY` is empty and that is not a bug.

## The one mistake to never make

`secrets get KEY` does **not** print the secret. It prints a JSON status object and
pre-authorizes the key for this session:

```console
$ secrets get OPENAI_API_KEY
{"key":"OPENAI_API_KEY","tier":"agent"}
```

That JSON **is not the value**. It is not a placeholder, it is not a truncated key, and its
character count means nothing. If you were about to report that a key "looks like a
placeholder" or is "only 14 characters", you are reading the status object — re-read this
section instead of telling the human their key is broken.

## Grant lifetime: not minutes

Once a human-tier key is granted, it stays granted **for the session's entire lifetime**. It
does not expire after a few minutes, after a tool call boundary, or because "a while" has
passed. If a key that was granted earlier in this session suddenly fails, the actual causes
are:

- **The daemon restarted.** It lost every registration and grant with it. Retry the command
  **once** — the plugin re-registers automatically — and expect one fresh touch.
- **The session ended, or was replaced** (`/new` or an equivalent session switch). Each
  session has its own grants; a new one starts with none.
- **`secrets lock` ran.** It wipes every grant on the daemon, for every session, on purpose.
- **The key's backing file was edited or rotated.** The daemon invalidates a grant the moment
  the ciphertext it decrypted changes; the next request needs a fresh touch.
- **The 12-hour backstop expired.** Vanishingly unlikely inside a normal session.

"Grants expire quickly" is a superstition, not a fact — forming it and blaming the broker for
an unrelated failure (a typo'd key name, a missing config entry, your own retry loop) is
exactly the mistake this section exists to prevent. Anything else means the grant is **not**
the problem — read the error table below.

## Request before unattended work

Do this **at the start of a task**, while the human is at the keyboard — never mid-flight
into long unattended work:

1. Run `secrets list` and work out every human-tier key the task will need.
2. For each one, **announce it in chat before requesting it**: "Requesting `DEEL_API_KEY` —
   your YubiKey will blink; please touch it."
3. Call `secrets_request(KEY)` (or run `secrets get KEY`, which triggers the same approval
   flow) and wait for the grant before moving to the next key.

A request that nobody is watching **times out after 90 seconds** and the daemon reports
`TIMEOUT` — that is not a broker error, it is an unwatched request expiring. Starting a long
unattended run and only then discovering a key needs a touch means the run dies waiting on a
human who was never told to look. Front-load every request while attention is on you.

## One at a time

Never fire multiple `secrets_request` (or `secrets get KEY`) calls in parallel. The daemon
services one YubiKey decrypt at a time, and each key needs its own physical touch a human
can attribute to a specific request. Parallel requests just stack blinks nobody can tell
apart: they queue one at a time, any the human does not touch dies as `TIMEOUT` after 90
seconds, and stacking more than three pending requests fails immediately with
`TOO_MANY_PENDING`. Request, wait for the grant (or denial), then request the next.

## Subagents inherit the parent's grants — don't re-request

Grants belong to the whole in-process session tree, not to one call. In omp, every subagent
you dispatch automatically shares the root session's token and its grants; nothing separate
needs to run for a subagent to use a key the root already has. Concretely:

- Get every human-tier grant the task needs **in the parent**, before dispatching subagents.
- A subagent must **never** be the one to call `secrets_request` for a human-tier key — it has
  no way to guarantee the human is watching for its blink, and the grant would land on the
  shared session anyway. If a subagent hits a key it does not have, that is a sign the parent
  skipped the request-before-dispatch step above, not something for the subagent to fix.

## What to run

**Running a command that needs the secret — do this by default:**

```bash
secrets OPENAI_API_KEY -- python script.py
secrets SLACK_MCP_XOXP_TOKEN -- slack-mcp-server
secrets AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY -- terraform apply
```

The value is placed in the child process's environment and never printed, so it cannot
land in the transcript. Prefer this over every other form.

**Only when you genuinely need the bytes** (piping into a file, building a header):

```bash
secrets get OPENAI_API_KEY --value
```

This prints the secret, so it will appear in the transcript. Never run it just to look at
a key, and never paste its output into a message.

**Other forms:**

| Command | Does |
|---|---|
| `secrets get KEY` | JSON status; pre-authorizes (prompts for a touch if the key needs one) |
| `secrets get KEY --value` | prints the secret |
| `secrets get KEY --no-request` | status only; never prompts |
| `secrets KEY [KEY2 ...] -- cmd` | runs `cmd` with the keys in its environment |
| `secrets list` | every key name and its tier; never decrypts |
| `secrets grants` | which human-tier keys are currently unlocked |
| `secrets_request(KEY)` tool call | requests approval only; never returns the value |

## Two tiers

`secrets list` marks each key. **Agent-tier** keys resolve locally and need no approval.
**Human-tier** keys are unlocked by a physical YubiKey touch: one request per key per
session makes the human's key blink, and every later request for that same key in that same
session is free. In omp, "that same session" is the whole session tree — root or any of its
subagents share one grant. In OpenCode, registration is per session id; a sibling session
does not inherit another session's grants.

## When it refuses

Errors start with `AGENT NOTICE: ask the human; do not retry-loop.` Take that literally: with
one exception (`the broker restarted`, below), re-running will not help, and repeated attempts
make the human's key blink repeatedly.

| Message contains | Means | Do |
|---|---|---|
| `not human-tier` | no approval needed for this key | read it directly with `--value` or inject it |
| `neither a terminal tty nor a session token` | non-interactive context with no session | ask the human to run it, or run inside the agent session |
| `outside that session's process tree` | the token came from elsewhere | run the request from this session |
| `secretsd failed while decrypting` | daemon-side sops failure — **not** a missed touch, which is reported as `TIMEOUT` instead | `journalctl --user -u secretsd` for the daemon's sops stderr |
| `secret 'X' not found` | the key genuinely is not configured | ask the human to add it; do not invent a value |
| `the broker restarted` | the daemon restarted, so its registrations and grants are gone | run the command **once** more: the plugin re-registers between commands. Expect a touch. If it fails twice, tell the human |
| `TIMEOUT` / `timed out` | nobody touched the key within 90s of the request | you skipped announcing the request first; tell the human and request again, watched this time |
| `TOO_MANY_PENDING` | you (or a parallel call) already have requests queued on this scope | stop; wait for the pending request to resolve before requesting again |

## Never

- Never paste a secret's value into a message, a commit, a log, or a file.
- Never write a secret into a script, a `.env`, or a shell history line.
- Never conclude a key is wrong from `secrets get` output — that output is status, not the key.
- Never retry after an `AGENT NOTICE`, with one exception: `the broker restarted` clears itself once the plugin re-registers, so run that command **once** more. Never loop.
- Never conclude "grants expire quickly" from a failure — it is one of the causes in Grant lifetime above, or an unrelated bug, never the grant itself.
- Never request keys mid-flight into unattended work, and never fire `secrets_request` calls in parallel — see the two sections above.
- Never have a subagent request a human-tier key; request it in the parent before dispatching.
