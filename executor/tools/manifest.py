"""MCP tool manifest (pinned hash, logged at session start). CONTRACTS.md v2 §4.5. Owner: WS-E.

Contract data: tool names and argument schemas the agent sees. There is no IBAN argument on payment.propose (P3).
"""
from __future__ import annotations

from typing import Any

from executor.canonical import canonical_json, sha256_hex

_STR = {"type": "string"}
_HINTS = {"type": "array", "items": {"type": "object", "properties": {"source": {"enum": ["agent"]},
                                                                      "text": {"type": "string", "maxLength": 200}}}}

TOOL_MANIFEST: dict[str, dict[str, Any]] = {
    "inbox.list": {"args": {}, "effect": "read"},
    "inbox.read": {"args": {"email_id": _STR}, "effect": "read_untrusted"},
    "invoice.extract": {"args": {"doc_id": _STR}, "effect": "read_untrusted"},
    "vendor.lookup": {"args": {"vendor_id": _STR, "ico": _STR}, "effect": "read"},
    "mandate.status": {"args": {}, "effect": "read"},
    "payment.propose": {"args": {"vendor_id": _STR, "invoice_ref": _STR, "invoice_no": _STR,
                                 "amount_minor": {"type": "integer", "minimum": 1}, "currency": {"enum": ["CZK", "EUR"]},
                                 "vs": _STR, "due": _STR,
                                 "reason_code": {"enum": ["DUE", "PARTIAL", "ADVANCE", "OTHER"]}, "hints": _HINTS},
                        "effect": "propose", "executor": "POST /proposals"},
    "payee.request_change": {"args": {"vendor_id": _STR, "new_iban": _STR,
                                      "evidence_ids": {"type": "array", "items": _STR}, "hints": _HINTS},
                             "effect": "propose", "executor": "POST /changes"},
    "mail.send_template": {"args": {"to": _STR, "template_id": _STR, "vars": {"type": "object"}},
                           "effect": "egress", "executor": "POST /egress"},
}
# Decoys: not served; Cedar forbids them for principal type Agent so escalation attempts are logged.
DECOY_TOOLS: list[str] = ["mandate.write", "vendor.write"]


def manifest_sha256() -> str:
    """sha256(canonical_json({"tools": TOOL_MANIFEST, "decoys": DECOY_TOOLS})) - pinned per agent session."""
    return sha256_hex(canonical_json({"tools": TOOL_MANIFEST, "decoys": DECOY_TOOLS}))
