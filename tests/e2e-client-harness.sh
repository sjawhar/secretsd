#!/usr/bin/env bash
# Drives the built daemon and client through the real-sops human-tier flow.
set -euo pipefail

readonly skip_status=77
readonly token='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly session='e2e-client'
readonly human_key='E2E_KEY'
readonly local_human_key='LOCAL_KEY'
readonly root2_human_key='ROOT2_KEY'
readonly agent_key='AGENT_KEY'
readonly human_value='value-for-e2e-client'
readonly local_human_value='value-for-local-human'
readonly root2_human_value='value-for-root2-human'
readonly agent_value='value-for-agent-client'
readonly grants_pattern=$'^KEY\tSCOPE\tAGE\nE2E_KEY\tsession\t[0-9]+s\nLOCAL_KEY\tsession\t[0-9]+s\nROOT2_KEY\tsession\t[0-9]+s$'

report() {
  printf 'e2e-client: %s\n' "$1"
}

fail() {
  printf 'e2e-client: FAIL: %s\n' "$1" >&2
  exit 1
}

skip() {
  report "SKIP: $1"
  exit "$skip_status"
}

after_register=false
if [[ "${1:-}" == --after-register ]]; then
  after_register=true
  shift
fi

if (($# != 3)); then
  printf 'usage: %s PATH/TO/secrets serve PATH/TO/secrets\n' "$0" >&2
  exit 64
fi

readonly daemon="$1"
readonly daemon_subcommand="$2"
readonly client="$3"

if [[ "$daemon_subcommand" != serve ]]; then
  fail 'the daemon subcommand must be serve'
fi

if ! command -v sops >/dev/null; then
  skip 'sops is unavailable'
fi
if ! command -v age-keygen >/dev/null; then
  skip 'age-keygen is unavailable'
fi
if ! command -v python3 >/dev/null; then
  skip 'python3 is unavailable for the REGISTER protocol frame'
fi
if [[ ! -x "$daemon" || ! -x "$client" ]]; then
  fail 'the built secrets binary must be executable'
fi

readonly real_sops="$(command -v sops)"
readonly age_key_file="${SOPS_AGE_KEY_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt}"
if [[ ! -r "$age_key_file" ]]; then
  skip "disk-resident age key is unavailable at $age_key_file"
fi

if ! agent_recipient="$(awk '/^AGE-SECRET-KEY-/{print; exit}' "$age_key_file" | age-keygen -y -)"; then
  skip 'the disk-resident age key has no usable ordinary age identity'
fi
readonly agent_recipient
if [[ ! "$agent_recipient" =~ ^age1 ]]; then
  skip 'the disk-resident age key has no usable public recipient'
fi

mkdir -p /tmp/opencode
if [[ "$after_register" == true ]]; then
  readonly scratch="${E2E_CLIENT_HARNESS_SCRATCH:?post-registration scratch path is required}"
  daemon_pid="${E2E_CLIENT_HARNESS_DAEMON_PID:?post-registration daemon pid is required}"
else
  readonly scratch="$(mktemp -d /tmp/opencode/secretsd-e2e-client.XXXXXX)"
  daemon_pid=''
fi
readonly dotfiles_dir="$scratch/dotfiles"
readonly human_dir="$dotfiles_dir/secrets.human.d"
readonly private_dir="$scratch/private"
readonly private_human_dir="$private_dir/secrets.human.d"
readonly socket="$scratch/secretsd.sock"
readonly token_file="$scratch/session.token"
readonly harness_bin="$scratch/bin"
readonly sops_log="$scratch/real-sops-invocations.log"
readonly daemon_log="$scratch/daemon.log"
readonly daemon_config="$scratch/config.toml"

cleanup() {
  local status=$?
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$scratch"
  exit "$status"
}
trap cleanup EXIT

assert_sops_counts() {
  local expected_total="$1"
  local expected_daemon="$2"
  local phase="$3"
  local counts
  counts="$(python3 - "$sops_log" <<'PY'
import pathlib
import sys

calls = [call.split(b"\0") for call in pathlib.Path(sys.argv[1]).read_bytes().splitlines() if call]
daemon_calls = sum(call[-2].startswith(b"/proc/self/fd/") for call in calls)
print(len(calls), daemon_calls)
PY
)"
  local actual_total actual_daemon
  read -r actual_total actual_daemon <<< "$counts"
  [[ "$actual_total" == "$expected_total" && "$actual_daemon" == "$expected_daemon" ]] || {
    fail "$phase invoked real sops total=$actual_total daemon=$actual_daemon; expected total=$expected_total daemon=$expected_daemon"
  }
}

run_client() {
  env -i \
    PATH="$harness_bin:$PATH" \
    HOME="$HOME" \
    SECRETSD_CONFIG="$daemon_config" \
    SECRETSD_SOCK="$socket" \
    SECRETSD_SESSION_TOKEN_FILE="$token_file" \
    SOPS_AGE_KEY_FILE="$age_key_file" \
    REAL_SOPS_BIN="$real_sops" \
    REAL_SOPS_LOG="$sops_log" \
    "$client" "$@"
}

if [[ "$after_register" == false ]]; then
  report '1/12 preparing scratch files and real-sops wrapper'
  umask 077
  mkdir -p "$human_dir" "$private_human_dir" "$harness_bin"
  printf '[source.dotfiles]\npath = "%s"\n\n[source.private]\npath = "%s"\n' "$dotfiles_dir" "$private_dir" > "$daemon_config"

  # The wrapper only records argv and execs the real sops binary; fake-sops remains
  # reserved for unit fixtures that need deterministic fake plaintext.
  cat > "$harness_bin/sops" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\0' "$@" >> "$REAL_SOPS_LOG"
printf '\n' >> "$REAL_SOPS_LOG"
exec "$REAL_SOPS_BIN" "$@"
EOF
  chmod 700 "$harness_bin/sops"

  # This disposable recipient stands in for the unavailable hardware recipient.
  # If filename override ever selects this human rule, the daemon cannot decrypt.
  age-keygen -o "$scratch/unavailable-human.age" >/dev/null 2>&1
  readonly unavailable_human_recipient="$(age-keygen -y "$scratch/unavailable-human.age")"
  cat > "$scratch/.sops.yaml" <<EOF
creation_rules:
  - path_regex: secrets\\.human\\.d/[^/]+\\.env$
    age: $unavailable_human_recipient
  - path_regex: .*
    age: $agent_recipient
EOF
  printf '%s=%s\n' "$human_key" "$human_value" > "$scratch/p.env"
  printf '%s=%s\n' "$local_human_key" "$local_human_value" > "$scratch/local.env"
  printf '%s=%s\n' "$root2_human_key" "$root2_human_value" > "$scratch/root2.env"
  printf '%s=%s\n' "$agent_key" "$agent_value" > "$scratch/agent.env"

  report '2/12 encrypting the human and agent fixtures with real sops'
  (
    cd "$scratch"
    "$real_sops" --filename-override "$scratch/plain.env" --input-type dotenv --output-type dotenv -e "$scratch/p.env" > "$human_dir/$human_key.env"
    "$real_sops" --filename-override "$scratch/plain.env" --input-type dotenv --output-type dotenv -e "$scratch/local.env" > "$human_dir/$local_human_key.local.env"
    "$real_sops" --filename-override "$scratch/plain.env" --input-type dotenv --output-type dotenv -e "$scratch/root2.env" > "$private_human_dir/$root2_human_key.env"
    "$real_sops" --filename-override "$scratch/secrets.env" --input-type dotenv --output-type dotenv -e "$scratch/agent.env" > "$dotfiles_dir/secrets.env"
  )

  report '3/12 confirming filename override chose the disk-age recipient'
  grep -F --quiet "$agent_recipient" "$human_dir/$human_key.env" || fail 'human fixture lacks the disk-age recipient'
  if grep -F --quiet "$unavailable_human_recipient" "$human_dir/$human_key.env"; then
    fail 'human fixture matched the unavailable human-recipient creation rule'
  fi

  report '4/12 starting the built daemon on the scratch socket'
  # The daemon loads its source root from config.toml, while the client resolves
  # the same root through SECRETSD_CONFIG.
  # Optional memlock is local-harness-only; production keeps the strict default.
  env -i \
    PATH="$harness_bin:$PATH" \
    HOME="$scratch" \
    SECRETSD_MEMLOCK=optional \
    RUST_LOG=info \
    SECRETSD_SOCKET="$socket" \
    SECRETSD_CONFIG="$daemon_config" \
    SECRETSD_SOPS_BIN="$harness_bin/sops" \
    SOPS_AGE_KEY_FILE="$age_key_file" \
    REAL_SOPS_BIN="$real_sops" \
    REAL_SOPS_LOG="$sops_log" \
    "$daemon" "$daemon_subcommand" > "$daemon_log" 2>&1 &
  daemon_pid=$!
  for _ in {1..100}; do
    [[ -S "$socket" ]] && break
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      fail 'daemon exited before creating its scratch socket'
    fi
    sleep 0.05
  done
  [[ -S "$socket" ]] || fail 'daemon did not create its scratch socket'

  report '5/12 registering the session token over the real daemon protocol'
  # Replacing this shell preserves the registered pid for the client descendants.
  export E2E_CLIENT_HARNESS_SCRATCH="$scratch"
  export E2E_CLIENT_HARNESS_DAEMON_PID="$daemon_pid"
  exec python3 - "$socket" "$token" "$session" "$$" "$0" "$daemon" "$daemon_subcommand" "$client" <<'PY'
import os
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])
sock.sendall(f"REGISTER\ttoken={sys.argv[2]}\tsession={sys.argv[3]}\tpid={sys.argv[4]}\n".encode())
response = sock.makefile("rb").readline()
if response != b"OK\n":
    raise SystemExit(f"REGISTER failed with {response!r}")
os.execvp("bash", ["bash", sys.argv[5], "--after-register", *sys.argv[6:]])
PY
fi
printf '%s' "$token" > "$token_file"
chmod 600 "$token_file"

report '6/12 fetching the human value through the real client'
first_get="$(run_client get "$human_key" --value)"
[[ "$first_get" == "$human_value" ]] || fail 'first get returned an unexpected value'
assert_sops_counts 2 1 'first get'
report '6/12 get returned the expected value [redacted]; real-sops total=2 daemon=1'

report '7/12 fetching the cached human value through the real client'
second_get="$(run_client get "$human_key" --value)"
[[ "$second_get" == "$human_value" ]] || fail 'cached get returned an unexpected value'
assert_sops_counts 3 1 'cached get'
report '7/12 cached get returned the expected value [redacted]; real-sops total=3 daemon=1'

report '8/12 injecting the cached value into a child environment'
injected="$(run_client "$human_key" -- sh -c 'printf %s "$E2E_KEY"')"
[[ "$injected" == "$human_value" ]] || fail 'injection returned an unexpected child value'
assert_sops_counts 4 1 'injection'
report '8/12 injection returned the expected value [redacted]; real-sops total=4 daemon=1'

report '9/12 fetching a root1 local human key and checking its audit source'
local_get="$(run_client get "$local_human_key" --value)"
[[ "$local_get" == "$local_human_value" ]] || fail 'local get returned an unexpected value'
grep -E --quiet 'source.*dotfiles\.local' "$daemon_log" || fail 'local key audit did not record source=dotfiles.local'
assert_sops_counts 6 2 'local human get'
report '9/12 local human get returned the expected value [redacted]; real-sops total=6 daemon=2'

report '10/12 fetching a human key that exists only in the second source root'
root2_get="$(run_client get "$root2_human_key" --value)"
[[ "$root2_get" == "$root2_human_value" ]] || fail 'root2 get returned an unexpected value'
assert_sops_counts 8 3 'root2 human get'
report '10/12 root2 human get returned the expected value [redacted]; real-sops total=8 daemon=3'

report '11/12 listing both tiers and active grants'
listing="$(run_client list)"
[[ "$listing" == $'AGENT_KEY\nE2E_KEY  (human tier: dotfiles)\nLOCAL_KEY  (human tier: dotfiles.local)\nROOT2_KEY  (human tier: private)' ]] || fail 'list returned unexpected tier names'
assert_sops_counts 9 3 'list'
grants="$(run_client grants)"
[[ "$grants" =~ $grants_pattern ]] || fail 'grants did not show every session grant'
assert_sops_counts 9 3 'grants'
report '11/12 list and grants returned expected redacted state; real-sops total=9 daemon=3'

report '12/12 locking the daemon and confirming every grant is cleared'
run_client lock
assert_sops_counts 9 3 'lock'
[[ "$(run_client grants)" == 'no active grants' ]] || fail 'lock did not clear the session grant'
assert_sops_counts 9 3 'post-lock grants'
report '12/12 lock cleared every grant; real-sops total=9 daemon=3'
report 'PASS: real daemon, real client, and real sops completed on scratch state'
