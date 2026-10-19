#!/usr/bin/env bash
# Build infra/build/lambda.zip: runtime deps (linux arm64, py3.12) + executor/ agent/ witness/ contracts/schemas.
# No trezorlib/streamlit/moto/pytest (C17). boto3 comes from the Lambda runtime. Owner: WS-E.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=infra/build/lambda
rm -rf infra/build && mkdir -p "$OUT"
export TZ=UTC
# runtime deps pinned from uv.lock (no dev/ui/host extras); boto3/botocore come from the Lambda runtime;
# manylinux_2_28 wheels: the python3.12 runtime is Amazon Linux 2023 (glibc 2.34)
uv export --quiet --frozen --no-dev --no-hashes --no-emit-project --format requirements-txt \
  | grep -v -E '^(boto3|botocore|s3transfer)==' > infra/build/requirements.lock
uv pip install --quiet --target "$OUT" --python-platform aarch64-manylinux_2_28 --python-version 3.12 \
  --only-binary=:all: --no-binary dkimpy -r infra/build/requirements.lock
cp -R executor agent witness vendor "$OUT"/  # vendor: executor.change imports vendor.portal
mkdir -p "$OUT/contracts" && cp -R contracts/schemas "$OUT/contracts/" && cp contracts/__init__.py "$OUT/contracts/"
# data snapshots only: no DEMO private keys (issuer/holder JWKs, DKIM PEMs) in any function, incl. the agent
rsync -a --exclude issuer_keys --exclude dkim_keys --exclude '*.pem' --exclude '*.jwk' data "$OUT/"
cp infra/lambda_src/*.py "$OUT"/
find "$OUT" -name "__pycache__" -prune -exec rm -rf {} +  # keep *.dist-info: importlib.metadata needs it
# deterministic zip (sorted, fixed mtime) so CodeSha256 is reproducible
(cd "$OUT" && find . -type f | LC_ALL=C sort | TZ=UTC xargs touch -t 202610190000 && \
  find . -type f | LC_ALL=C sort | zip -q -X -D ../lambda.zip -@)
ls -la infra/build/lambda.zip
python3 -c "import hashlib,base64;d=open('infra/build/lambda.zip','rb').read();h=hashlib.sha256(d);print('CodeSha256', base64.b64encode(h.digest()).decode(), h.hexdigest())"
