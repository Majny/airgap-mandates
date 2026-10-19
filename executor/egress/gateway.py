"""POST /egress implementation: allow or 403 egress_blocked + egress_block leaf. CONTRACTS.md §4.2.

Checks, all evaluated (findings are not short-circuited so the leaf shows every reason): E-ALLOWLIST, E-URLDATA on the
target and on URLs embedded in the content (markdown images), DLP over content + attachments + the target string,
E-SIZE, E-RATE (per-minute counter). E-GUARDRAILS (Bedrock ApplyGuardrail second opinion) runs only when
AIRGAP_GUARDRAIL_ID is set. Delivery itself is simulated: an allowed message is only recorded, never sent.

Owner: WS-E.
"""
from __future__ import annotations

import os
from typing import Any

from executor.canonical import sha256_hex
from executor.config import now
from executor.egress import allowlist, dlp
from executor.errors import ApiError, ErrorCode
from executor.store import shims

MAX_CONTENT_CHARS = 4000
MAX_ATTACHMENTS = 0  # attachments are stripped: any attachment is scanned and then refused (E-SIZE)
RATE_PER_MINUTE = 10
_REGISTRY_META_ID = "registry#meta"


def _vendors(store: Any) -> list[dict[str, Any]]:
    return [r for r in store.scan("registry") if r.get("vendor_id") != _REGISTRY_META_ID]


def _rate_count(store: Any, settings: Any) -> int:
    minute = now(settings).strftime("%Y%m%dT%H%M")
    return store.increment("counters", {"name": f"egress#{minute}"}, "n", 1)


def _guardrails_findings(text: str, settings: Any) -> list[dict[str, Any]]:
    gid = os.environ.get("AIRGAP_GUARDRAIL_ID")
    if not gid or not text:
        return []
    import boto3

    resp = boto3.client("bedrock-runtime", region_name=settings.aws_region).apply_guardrail(
        guardrailIdentifier=gid, guardrailVersion=os.environ.get("AIRGAP_GUARDRAIL_VERSION", "DRAFT"),
        source="OUTPUT", content=[{"text": {"text": text}}])
    if resp.get("action") != "GUARDRAIL_INTERVENED":
        return []
    return [{"rule_id": "E-GUARDRAILS", "detail": "Bedrock Guardrails sensitive-info intervened", "count": 1}]


def evaluate(req: dict[str, Any], *, vendors: list[dict[str, Any]], rate_count: int = 0) -> list[dict[str, Any]]:
    """Pure decision: findings for one egress request (empty list = allow)."""
    tool, target = req["tool"], req["target"]
    content = req.get("content") or ""
    attachments = req.get("attachments") or []
    findings: list[dict[str, Any]] = []
    if not allowlist.is_allowed(tool, target, vendors=vendors):
        dom = allowlist.target_domain(tool, target) or "malformed target"
        findings.append({"rule_id": "E-ALLOWLIST", "detail": f"{dom[:64]} not allowlisted", "count": 1})
    for url in ([target] if tool != "send_email" else []) + allowlist.urls_in(content):
        findings += allowlist.url_data_findings(url)
    findings += dlp.scan(content + "\n" + target, attachments, vendors=vendors)
    if len(content) > MAX_CONTENT_CHARS:
        findings.append({"rule_id": "E-SIZE", "detail": f"content {len(content)} chars > {MAX_CONTENT_CHARS}",
                         "count": 1})
    if len(attachments) > MAX_ATTACHMENTS:
        findings.append({"rule_id": "E-SIZE", "detail": "attachments not allowed", "count": len(attachments)})
    if rate_count > RATE_PER_MINUTE:
        findings.append({"rule_id": "E-RATE", "detail": f"{rate_count} messages this minute > {RATE_PER_MINUTE}",
                         "count": rate_count})
    order = {r: i for i, r in enumerate(dlp.RULE_ORDER)}
    return sorted(findings, key=lambda f: order[f["rule_id"]])


def handle_egress(req: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """Return allow body or raise ApiError(egress_blocked, details={'decision': ...})."""
    vendors = _vendors(store)
    findings = evaluate(req, vendors=vendors, rate_count=_rate_count(store, settings))
    if not findings:
        try:
            findings = _guardrails_findings(req.get("content") or "", settings)
        except Exception:  # noqa: BLE001 - second opinion only; its outage never blocks or allows on its own
            findings = []
    if not findings:
        return {"decision": "allow", "rule_ids": [], "findings": []}

    rule_ids = dlp.order_rule_ids(findings)
    decision = {"decision": "block", "rule_ids": rule_ids, "findings": findings}
    content_sha256 = sha256_hex((req.get("content") or "").encode("utf-8"))
    event = shims.make_event("egress_block", {"tool": req["tool"], "target": req["target"][:256],
                                              "rule_ids": rule_ids, "findings": findings,
                                              "content_sha256": content_sha256},
                             subject_id=req.get("context_ref"), actor="tools", settings=settings)
    shims.append(event, store=store, settings=settings)
    raise ApiError(ErrorCode.EGRESS_BLOCKED, "; ".join(f["detail"] for f in findings)[:200],
                   details={"decision": decision})
