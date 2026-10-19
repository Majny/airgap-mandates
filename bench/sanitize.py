"""A1 layer: input sanitiser (regex twin of Bedrock Guardrails prompt-attack filter) and egress DLP. Owner: WS-F.

ARCHITECTURE §11 A1 = A0 + Guardrails prompt-attack filter with input tags (or the regex sanitiser) + egress DLP.
This module is the regex sanitiser and a deterministic DLP twin, so A1 runs offline and reproducibly. It is
deliberately the kind of filter teams ship today: it catches obvious payloads and is measured, not trusted.
"""
from __future__ import annotations

import base64
import re
from typing import Any

from bench.world import iban_valid

_INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above) (instructions|messages|rules)",
    r"disregard (all |any |the )?(previous|prior|above)",
    r"\b(system|assistant)\s*(prompt|message|override|note)\s*:",
    r"\bnew instructions?\b",
    r"\byou (must|should) now\b",
    r"\b(as an ai|as the ai|ai assistant|ap[- ]?clerk|agent)\b.{0,40}\b(must|should|is required|is instructed)\b",
    r"\bdo not (tell|inform|notify|mention)\b",
    r"\bwithout (verification|approval|confirming|checking)\b",
    r"<\s*/?\s*(system|instructions?|admin|override)\s*>",
    r"\b(cfo|ceo|director) (has )?(already )?approved\b",
    r"\burgent(ly)?\b.{0,40}\b(transfer|pay|wire)\b",
]
_INJ = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)

IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b")
ICO_RE = re.compile(r"\b\d{8}\b")
B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def sanitize(text: str, *, source: str) -> tuple[str, int]:
    """Drop lines that look like prompt injection; wrap the rest in spotlighting tags. Returns (text, n_dropped)."""
    kept, dropped = [], 0
    for line in (text or "").splitlines():
        if _INJ.search(line):
            dropped += 1
            continue
        kept.append(line)
    body = "\n".join(kept)
    return f"<untrusted source=\"{source}\">\n{body}\n</untrusted>", dropped


def dlp_findings(content: str, *, registry_ibans: set[str], registry_icos: set[str]) -> list[dict[str, Any]]:
    """Deterministic DLP: IBAN (mod-97), registry IBAN/account fragments, ICO list, base64/hex blobs."""
    findings: list[dict[str, Any]] = []
    flat = content.upper()
    for m in IBAN_RE.finditer(flat):
        cand = m.group(0).replace(" ", "")
        if iban_valid(cand):
            findings.append({"rule_id": "E-IBAN", "detail": cand[:4] + "..", "count": 1})
    compact = flat.replace(" ", "")
    for iban in registry_ibans:
        if iban[-10:] in compact and not any(f["rule_id"] == "E-IBAN" for f in findings):
            findings.append({"rule_id": "E-ACCT", "detail": ".." + iban[-4:], "count": 1})
    icos = [m.group(0) for m in ICO_RE.finditer(content) if m.group(0) in registry_icos]
    if len(icos) >= 2:
        findings.append({"rule_id": "E-ICO", "detail": "registry ICO list", "count": len(icos)})
    for m in B64_RE.finditer(content):
        try:
            base64.b64decode(m.group(0) + "==", validate=False)
            findings.append({"rule_id": "E-BLOB", "detail": "encoded payload", "count": 1})
            break
        except Exception:
            continue
    return findings
