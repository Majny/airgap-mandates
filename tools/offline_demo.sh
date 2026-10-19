#!/usr/bin/env bash
# "Wi-Fi off" stage check of a pre-sealed demo bundle (tools/demo_bundle.py). No network needed.
# Usage: bash tools/offline_demo.sh [dir]   (default docs/audit/demo; `make offline-demo` builds noteverify first)
# Env: PY (default .venv/bin/python), NOTEVERIFY (default .local/bin/noteverify), QUORUM (verify_audit --quorum for
# step 2, e.g. log,w1,w2 = every checkpoint signed by the log and both witnesses; default log AND (w1 OR w2)).
# Exit 1 if any step fails.
# Owner: WS-B.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR_ARG="${1:-docs/audit/demo}"
if [ ! -d "$DIR_ARG" ]; then
  echo "no such directory: $DIR_ARG (run: make demo-bundle)" >&2
  exit 2
fi
DIR="$(cd "$DIR_ARG" && pwd)"
PY="${PY:-$ROOT/.venv/bin/python}"
NV="${NOTEVERIFY:-$ROOT/.local/bin/noteverify}"
cd "$ROOT"

for f in bundle.json trust-keys.json receipt.json checkpoint.txt; do
  if [ ! -f "$DIR/$f" ]; then
    echo "missing $DIR/$f (run: make demo-bundle)" >&2
    exit 2
  fi
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/airgap-offline.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
RESULTS=()

banner() { printf '\n==================================================\n %s\n==================================================\n' "$1"; }
verdict() { # verdict <PASS|FAIL> <label>
  if [ "$1" = PASS ]; then
    printf '\n  ########  PASS  ########  %s\n' "$2"
  else
    printf '\n  !!!!!!!!  FAIL  !!!!!!!!  %s\n' "$2"
    FAILS=$((FAILS + 1))
  fi
  RESULTS+=("$1  $2")
}
short() { # verifier output, projector-sized: verdict line + problems only, wrapped
  grep -E 'RESULT|^  - |^  \.\.\. ' "$1" | sed "s#$DIR/##g" | fold -s -w 72 || true
}

if [ -f "$DIR/RED-BUNDLE.txt" ]; then
  echo "WARNING: RED-BUNDLE.txt present: written with --allow-red,"
  echo "         this bundle is NOT sealed (see that file)."
fi

LOGKEY="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["log"])' "$DIR/trust-keys.json")"
W1KEY="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["w1"])' "$DIR/trust-keys.json")"
W2KEY="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("w2") or "")' "$DIR/trust-keys.json")"
LOGNAME_="${LOGKEY%%+*}"

# 1. checkpoint signature, checked by code we did not write (stock golang.org/x/mod/sumdb/note)
banner "1/4 checkpoint note - stock Go sumdb/note"
if [ ! -x "$NV" ]; then
  echo "noteverify binary not found at $NV"
  echo "build it BEFORE going offline: make offline-demo (or go build in tools/noteverify)"
  verdict FAIL "1 checkpoint (noteverify missing)"
else
  set +e
  "$NV" "$DIR/checkpoint.txt" "$LOGKEY" "$W1KEY" ${W2KEY:+"$W2KEY"} >"$WORK/nv.out" 2>&1
  rc=$?
  set -e
  sed 's/ (stock sumdb\/note cannot verify this signature type)/ (*)/' "$WORK/nv.out" | fold -s -w 72
  echo "(*) witness cosignature: a type stock note cannot check;"
  echo "    step 2 checks it with the pinned witness key."
  if [ "$rc" -eq 0 ] && grep -qF "OK $LOGNAME_ " "$WORK/nv.out"; then
    verdict PASS "1 checkpoint signed by the log"
  else
    verdict FAIL "1 checkpoint (noteverify exit $rc)"
  fi
fi

# 2. full bundle, pinned keys, decide() replay on
banner "2/4 audit bundle - pinned keys, replay on"
echo "keys pinned from trust-keys.json (shipped with the bundle;"
echo "in real use the auditor gets them out of band, e.g. /health)"
[ -n "${QUORUM:-}" ] && echo "quorum on every checkpoint: $QUORUM"
set +e
"$PY" -m tools.verify_audit "$DIR/bundle.json" --trust-keys "$DIR/trust-keys.json" ${QUORUM:+--quorum "$QUORUM"} \
  >"$WORK/b.out" 2>&1
rc=$?
set -e
short "$WORK/b.out"
if [ "$rc" -eq 0 ]; then verdict PASS "2 bundle verifies"; else verdict FAIL "2 bundle (verifier exit $rc)"; fi

# 3. receipt of the last payment, pinned keys
banner "3/4 payment receipt - pinned keys, matches bundle"
set +e
"$PY" -m tools.verify_audit "$DIR/bundle.json" --receipt "$DIR/receipt.json" --trust-keys "$DIR/trust-keys.json" \
  >"$WORK/r.out" 2>&1
rc=$?
set -e
grep -E '^receipt:' "$WORK/r.out" | sed "s#$DIR/##g" | fold -s -w 72 || true
short "$WORK/r.out"
if [ "$rc" -eq 0 ]; then verdict PASS "3 receipt verifies"; else verdict FAIL "3 receipt (verifier exit $rc)"; fi

# 4. tamper: flip ONE byte of one execution leaf, the verifier must go red and name that leaf
banner "4/4 tamper one byte - must go RED"
set +e
info="$("$PY" -m tools.demo_bundle --tamper "$DIR/bundle.json" "$WORK/tampered.json" 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "$info"
  verdict FAIL "4 tamper (could not edit the bundle)"
else
  seq="$(echo "$info" | awk '{print $2}')"
  nbytes="$("$PY" -c 'import sys; a, b = (open(p, "rb").read() for p in sys.argv[1:]); print(sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b)))' "$DIR/bundle.json" "$WORK/tampered.json")"
  echo "edited: $info"
  echo "bytes changed: $nbytes"
  set +e
  "$PY" -m tools.verify_audit "$WORK/tampered.json" --trust-keys "$DIR/trust-keys.json" >"$WORK/t.out" 2>&1
  rc=$?
  set -e
  grep -E "RESULT|seq $seq:" "$WORK/t.out" | fold -s -w 72 || true
  if [ "$nbytes" = 1 ] && [ "$rc" -ne 0 ] && grep -q "seq $seq: leaf hash mismatch" "$WORK/t.out"; then
    verdict PASS "4 tamper caught at seq $seq"
  else
    verdict FAIL "4 tamper (bytes $nbytes, exit $rc, seq $seq not named)"
  fi
fi

banner "SUMMARY ($(basename "$DIR"))"
for r in "${RESULTS[@]}"; do echo "  $r"; done
if [ "$FAILS" -eq 0 ]; then
  printf '\n  ####  ALL PASS - verified offline  ####\n\n'
  exit 0
fi
printf '\n  !!!!  %d STEP(S) FAILED  !!!!\n\n' "$FAILS"
exit 1
