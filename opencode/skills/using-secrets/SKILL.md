---
name: using-secrets
description: "Use BEFORE running any command that needs an API key, token, password, or credential, and whenever a secret looks missing, wrong, truncated, or like a placeholder. This machine has no secrets in the environment — every key comes from the `secrets` CLI, and `secrets get KEY` does NOT print the value. Triggers on: secrets get, secrets list, API key, API token, access token, credential, OPENAI_API_KEY, ANTHROPIC_API_KEY, AIRTABLE_TOKEN, SLACK_MCP_XOXP_TOKEN, GROQ_API_KEY, DEEL_API_KEY, sk-, xoxp-, export KEY=, env var for a command, 'key is a placeholder', 'key looks wrong', 'invalid api key', 401, 403, authentication failed, sops, YubiKey touch, secretsd."
---

# Using the `secrets` CLI

Every credential on this machine comes from `secrets`. Nothing is pre-exported into the
environment, so a bare `echo $OPENAI_API_KEY` is empty and that is not a bug.

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

## Two tiers

`secrets list` marks each key. **Agent-tier** keys resolve locally and need no approval.
**Human-tier** keys are unlocked by a physical YubiKey touch: the first request in a
session makes the human's key blink, and every later request in that session is free.

`secrets get KEY` is therefore the polite way to start work — it asks for the touch once,
up front, without printing anything, and everything afterwards just works.

## When it refuses

Errors start with `AGENT NOTICE: ask the human; do not retry-loop.` Take that literally: with
one exception (`the broker restarted`, below), re-running will not help, and repeated attempts
make the human's key blink repeatedly.

| Message contains | Means | Do |
|---|---|---|
| `not human-tier` | no approval needed for this key | read it directly with `--value` or inject it |
| `neither a terminal tty nor a session token` | non-interactive context with no session | ask the human to run it, or run inside the agent session |
| `outside that session's process tree` | the token came from elsewhere | run the request from this session |
| `failure to spawn sops` | decryption failed, usually a missed touch | tell the human; ask them to touch the key |
| `secret 'X' not found` | the key genuinely is not configured | ask the human to add it; do not invent a value |
| `the broker restarted` | the daemon restarted, so its registrations and grants are gone | run the command **once** more: the plugin re-registers between commands. Expect a touch. If it fails twice, tell the human |

## Never

- Never paste a secret's value into a message, a commit, a log, or a file.
- Never write a secret into a script, a `.env`, or a shell history line.
- Never conclude a key is wrong from `secrets get` output — that output is status, not the key.
- Never retry after an `AGENT NOTICE`, with one exception: `the broker restarted` clears itself once the plugin re-registers, so run that command **once** more. Never loop.
