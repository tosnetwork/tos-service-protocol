#!/bin/bash
# Run scripts/service-actor-buyer-e2e.py on an isolated local PQ network in
# its own process group under a thermal guard.
#
# Required environment:
#   TOS_SOURCE        tos checkout providing test/tostester (run with its uv env)
#   TOS_BUILD         tos build directory with the PQ genesis tools
#   TOSCTL            tosctl built from the Service Actor PQ branch (owner-only perms)
#   E2E_WORKDIR       owner-private evidence and state directory
#   REGISTRY_CODE_BOC Native Registry code BOC (base64) the tosctl build embeds
#   ACTOR_CODE_HASH   tvm-cell-sha256:<hex> pinned Service Actor release
#   THERMAL_GUARD     script taking a process-group id to pause on heat
# Optional: E2E_BASE_PORT (tostester ports), E2E_RPC_PORTS (three JSON-RPC ports),
#   E2E_LIFECYCLE=1 (settlement lifecycle, hours of deadlines), and
#   E2E_EXECUTE=1 (paid execution in the private containerd sandbox) with
#   E2E_EXECUTOR (software-work-execute built from tos-ai, run under sudo -n)
#   and E2E_TOS_AI_COMMIT (the commit it was built from).
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "$here")
: "${TOS_SOURCE:?}" "${TOS_BUILD:?}" "${TOSCTL:?}" "${E2E_WORKDIR:?}" "${REGISTRY_CODE_BOC:?}" "${ACTOR_CODE_HASH:?}" "${THERMAL_GUARD:?}"
export E2E_BASE_PORT=${E2E_BASE_PORT:-47600}
export E2E_RPC_PORTS=${E2E_RPC_PORTS:-47680,47681,47682}
for port in $(seq "$E2E_BASE_PORT" $((E2E_BASE_PORT + 79))) ${E2E_RPC_PORTS//,/ }; do
  if ss -ltn "( sport = :$port )" | grep -q LISTEN; then
    echo "port $port is in use; choose another E2E_BASE_PORT/E2E_RPC_PORTS" >&2
    exit 2
  fi
done
mkdir -p "$E2E_WORKDIR" && chmod 700 "$E2E_WORKDIR"
export E2E_BIN="$E2E_WORKDIR/bin"
mkdir -p "$E2E_BIN"
(cd "$repo" && GOWORK=off go build -o "$E2E_BIN/" ./cmd/tos-service-buyer ./cmd/service-actor-e2e-fixture)
cd "$TOS_SOURCE"
export PYTHONPATH="$TOS_SOURCE/test/tostester/src"
setsid uv run --frozen python "$here/service-actor-buyer-e2e.py" > "$E2E_WORKDIR/run.log" 2>&1 &
pg=$!
echo "$pg" > "$E2E_WORKDIR/run.pgid"
"$THERMAL_GUARD" "$pg" > "$E2E_WORKDIR/guard.log" 2>&1 &
set +e
wait "$pg"
status=$?
set -e
# After the run has exited, no artifact may hold the run's vault master key
# or any master_key value. Only file names are printed, never the value.
leaks=0
for artifact in "$E2E_WORKDIR/run.log" "$E2E_WORKDIR/cli-transcript.jsonl" "$E2E_WORKDIR/rpc-transcript.jsonl" "$E2E_WORKDIR/evidence.json"; do
  [ -f "$artifact" ] || continue
  if { [ -s "$E2E_WORKDIR/private/scan-secrets" ] && grep -qF -f "$E2E_WORKDIR/private/scan-secrets" "$artifact"; } ||
     grep -qE 'master_key=[0-9A-Fa-f]{8,}' "$artifact"; then
    echo "secret found in $artifact" >&2
    leaks=1
  fi
done
tail -n 2 "$E2E_WORKDIR/run.log"
if [ "$status" = 0 ] && [ "$leaks" = 0 ]; then
  echo "ALL PASS"
  exit 0
fi
echo "FAIL"
exit 1
