#!/usr/bin/env bash
# Start trezor-user-env with a Safe 3 (T3B1) emulator reachable at udp:127.0.0.1:21324 (debuglink 21325).
# The emulator binds 127.0.0.1 inside the container, so a tiny UDP relay (udpfwd.py) re-exposes it;
# every published port is bound to 127.0.0.1 on the host only. Usage: tests/device/tenv.sh [T3B1|T3T1] [version]
set -euo pipefail
MODEL=${1:-T3B1}; VERSION=${2:-2.12.5-arm}; NAME=${AIRGAP_TENV_CONTAINER:-am-tenv}
HERE=$(cd "$(dirname "$0")" && pwd)
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$NAME" -p 127.0.0.1:9001:9001 \
  -p 127.0.0.1:21324:31324/udp -p 127.0.0.1:21325:31325/udp ghcr.io/trezor/trezor-user-env:latest >/dev/null
docker cp "$HERE/udpfwd.py" "$NAME:/udpfwd.py"
docker exec -d "$NAME" python3 /udpfwd.py 21324 21325
for _ in $(seq 60); do
  .venv/bin/python -c "import websocket; websocket.create_connection('ws://127.0.0.1:9001/', timeout=5).recv()" 2>/dev/null && break
  sleep 3
done
.venv/bin/python -c "
from tests.device.oracle import start_emulator; start_emulator('$MODEL', '$VERSION'); print('emulator $MODEL $VERSION up at udp:127.0.0.1:21324')"
