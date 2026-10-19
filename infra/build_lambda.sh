#!/usr/bin/env bash
# Build infra/build/lambda.zip: runtime deps (linux arm64, py3.12) + executor/ agent/ witness/ contracts/schemas.
# No trezorlib/streamlit/moto/pytest (C17). boto3 comes from the Lambda runtime. Owner: WS-E.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=infra/build/lambda
rm -rf infra/build && mkdir -p "$OUT"
DEPS=$(python3 - <<'PY'
import tomllib
deps = tomllib.load(open("pyproject.toml", "rb"))["project"]["dependencies"]
print(" ".join(d for d in deps if not d.startswith("boto3")))
PY
)
uv pip install --quiet --target "$OUT" --python-platform aarch64-manylinux2014 --python-version 3.12 \
  --only-binary=:all: --no-binary dkimpy $DEPS
cp -R executor agent witness "$OUT"/
mkdir -p "$OUT/contracts" && cp -R contracts/schemas "$OUT/contracts/" && cp contracts/__init__.py "$OUT/contracts/"
[ -d data ] && cp -R data "$OUT/" || true
cp infra/lambda_src/*.py "$OUT"/
find "$OUT" -name "__pycache__" -prune -exec rm -rf {} +  # keep *.dist-info: importlib.metadata needs it
# deterministic zip (sorted, fixed mtime) so CodeSha256 is reproducible
(cd "$OUT" && find . -type f | LC_ALL=C sort | TZ=UTC xargs touch -t 202610190000 && \
  find . -type f | LC_ALL=C sort | zip -q -X -D ../lambda.zip -@)
ls -la infra/build/lambda.zip
python3 -c "import hashlib,base64;d=open('infra/build/lambda.zip','rb').read();h=hashlib.sha256(d);print('CodeSha256', base64.b64encode(h.digest()).decode(), h.hexdigest())"
