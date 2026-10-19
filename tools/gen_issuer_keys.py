"""Generate DEMO-ONLY ES256 keys for the simulated SD-JWT VC issuers and supplier holder wallets. CONTRACTS.md v2 §11.

Writes data/issuer_keys/<class>.jwk (supplier-erp, supplier-bank, registry) and holder-<ico>.jwk per fictitious
vendor, plus a README. These are fictitious demo keys committed in clear text; never use them for anything real.
Owner: WS-D.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from executor.attest.sdjwt import generate_key, private_jwk, thumbprint
from executor.issuers.issuer import ISSUER_URLS

VENDOR_ICOS = ("12345678", "87654321", "99887762")  # ACME s.r.o., Beta Servis a.s., Gamma Tisk s.r.o. (fictitious)

README = """# DEMO-ONLY issuer and holder keys (fictitious)

These ES256 (P-256) private JWKs are **fictitious demo keys** for the AirGap Mandates hackathon. They belong to
SIMULATED organisations (no real bank, ERP vendor or registry) and are committed in clear text on purpose.
Never use them outside the demo.

- `supplier-erp.jwk`, `supplier-bank.jwk`, `registry.jwk`: SD-JWT VC issuer keys (`iss` inside each file).
- `holder-<ico>.jwk`: the supplier wallet key bound via `cnf.jwk`; it signs the KB-JWT.

Regenerate with `.venv/bin/python -m tools.gen_issuer_keys --force` (changes the pins: re-seed the registry).
"""


def write_keys(out: Path, *, force: bool = False) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    entries = [(cls, {"iss": iss, "issuer_class": cls}) for cls, iss in ISSUER_URLS.items()]
    entries += [(f"holder-{ico}", {"holder_of": ico}) for ico in VENDOR_ICOS]
    written = []
    for name, meta in entries:
        path = out / f"{name}.jwk"
        if path.exists() and not force:
            continue
        jwk = private_jwk(generate_key())
        doc = {**jwk, "kid": thumbprint(jwk), **meta, "demo_only": True}
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        written.append(path)
    (out / "README.md").write_text(README)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data/issuer_keys")
    ap.add_argument("--force", action="store_true", help="overwrite existing keys")
    args = ap.parse_args(argv)
    for p in write_keys(Path(args.out), force=args.force):
        print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
