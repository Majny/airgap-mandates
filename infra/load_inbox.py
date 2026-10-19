"""Load data/emails/*.eml into the AWS inbox the production way: as the airgap-ingest role via POST /ingest
(the executor stores the raw .eml in the inbox bucket and the row with its ingest-time DKIM verdict). Idempotent:
email_id = sha256 of the raw bytes, so a re-run rewrites the same rows. Owner: WS-E.

Usage: python -m infra.load_inbox --url https://<api>/prod [--dir data/emails]
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from infra.aws_e2e import signed_call


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--dir", default="data/emails")
    a = ap.parse_args()
    call = signed_call(a.url.rstrip("/"))
    manifest = {r["file"]: r for r in json.loads((Path(a.dir) / "manifest.json").read_text())}
    for f in sorted(Path(a.dir).glob("*.eml")):
        raw = f.read_bytes()
        # no received_at: the sender-controlled Date header must not set our receive time (domain first-seen, age
        # facts); the executor stamps it on ingest
        body = {"raw_b64": base64.b64encode(raw).decode()}
        st, r = call("POST", "/ingest", body, "ingest")
        want = manifest.get(f.name, {}).get("email_id")
        ok = st in (200, 201) and (want is None or r.get("email_id") == want)
        print(f"{'OK ' if ok else 'ERR'} {st} {f.name:<38} {r.get('email_id', r)}")


if __name__ == "__main__":
    main()
