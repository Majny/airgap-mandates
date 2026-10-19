# DEMO-ONLY DKIM keys (fictitious)

These RSA-2048 private keys are **fictitious demo keys** for the AirGap Mandates email fixtures. They belong to
no real organisation, are published on purpose, and must never be used to sign real mail. The domains
(`acme.cz`, `betaservis.cz`, `gammatisk.cz`, `acme-cz.com`) stand for fictitious vendors and a fictitious
attacker in this demo; any resemblance to real domains is coincidental.

- File name: `<domain>.<selector>.pem` (selector `demo2026`).
- Created once by `tools/gen_emails.py` if absent; the matching public keys are written to
  `data/dns_snapshot.json` (`<selector>._domainkey.<domain>` TXT records), which F-DKIM resolves offline.
- Deleting a key changes every signature, every `email_id` (`eml_<16 hex of sha256(raw)>`) and the dns snapshot hash.
