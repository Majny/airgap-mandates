# DEMO-ONLY issuer and holder keys (fictitious)

These ES256 (P-256) private JWKs are **fictitious demo keys** for the AirGap Mandates hackathon. They belong to
SIMULATED organisations (no real bank, ERP vendor or registry) and are committed in clear text on purpose.
Never use them outside the demo.

- `supplier-erp.jwk`, `supplier-bank.jwk`, `registry.jwk`: SD-JWT VC issuer keys (`iss` inside each file).
- `holder-<ico>.jwk`: the supplier wallet key bound via `cnf.jwk`; it signs the KB-JWT.

Regenerate with `.venv/bin/python -m tools.gen_issuer_keys --force` (changes the pins: re-seed the registry).
