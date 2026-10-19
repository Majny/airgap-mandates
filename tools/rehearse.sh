#!/usr/bin/env bash
# Full stage rehearsal on AWS in one command (`make rehearse`): preflight -> reset + inbox -> S1 (physical Safe 3)
# -> S2 -> S3 -> S5 (Wi-Fi off). Pauses between beats, times each beat, logs to .local/rehearsal/<ts>.log.
# Env: AWS_PROFILE (default hackathon), API (default from infra/evidence/post_deploy.json),
#      RESET=0 skips the AWS reset (S1 then fails if it already ran), PREFLIGHT=0 skips preflight,
#      YES=1 skips the confirmations. Owner: orchestrator.
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE=${AWS_PROFILE:-hackathon}
PY=.venv/bin/python
API=${API:-$($PY -c "import json;print(json.load(open('infra/evidence/post_deploy.json'))['api_url'])")}
LOG=.local/rehearsal/$(date +%Y%m%d-%H%M%S).log
mkdir -p .local/rehearsal
exec > >(tee -a "$LOG") 2>&1

TIMES=()
banner() { printf '\n\033[1m==== %s ====\033[0m\n' "$1"; }
pause() { [ "${YES:-0}" = 1 ] || read -r -p $'\n'"$1 [Enter] " _ </dev/tty; }
beat() {  # beat <name> <command...>: run, time, stop on failure
  local name=$1 t0=$SECONDS; shift
  banner "$name"
  if "$@"; then TIMES+=("$(printf '%-28s %4ss  OK' "$name" $((SECONDS - t0)))")
  else TIMES+=("$(printf '%-28s %4ss  FAILED' "$name" $((SECONDS - t0)))"); summary; exit 1; fi
}
summary() {
  banner "SUMMARY ($API)"
  printf '%s\n' "${TIMES[@]}"
  echo "log: $LOG"
}

echo "AirGap rehearsal -> $API (profile $AWS_PROFILE)"
[ "${PREFLIGHT:-1}" = 0 ] || beat "preflight" $PY -m tools.preflight

if [ "${RESET:-1}" = 1 ]; then
  pause "Wipe and re-seed the AWS demo state (S1 runs once per reset)?"
  beat "reset + inbox" bash -c "AIRGAP_BACKEND=aws AWS_REGION=eu-central-1 AIRGAP_EXECUTOR_URL=$API \
    $PY -m infra.reset_state --yes && $PY -m infra.load_inbox --url $API"
fi

pause "S1: unlock the Safe 3. Hold 1 = MANDATE, then the agent pays 3 invoices, hold 2 = Delta 125000.50 CZK."
beat "S1 mandate + agent + step-up" $PY -m host.signer s1 --with-agent --url "$API"

pause "S2: lookalike BEC + escalation (one PAY hold inside the escalation step)."
beat "S2 lookalike + escalation" $PY -m host.signer scene s2 --url "$API"

pause "S3: takeover (device stays dark), then the legit change (clerk CHG hold)."
beat "S3 takeover + legit change" $PY -m host.signer scene s3 --url "$API"

banner "S5 seal (online)"
beat "S5 checkpoint + seal" bash -c "make -s checkpoint-now >/dev/null && make -s demo-s5"
pause "S5: turn Wi-Fi OFF now."
beat "S5 offline verify" bash tools/offline_demo.sh .local/demo/s5
echo; echo "Wi-Fi can go back on."
summary
