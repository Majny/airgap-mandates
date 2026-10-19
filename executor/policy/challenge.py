"""Challenge issuing and lookup (CONTRACTS.md v2 §2.3, §3.1 `nonces`, conventions "Nonce").

One function issues every challenge (MANDATE, PAY, CHG, CHG_REJECT, ENROLL, VENDOR_ATTEST): 8-hex displayed nonce
unique among all challenges (conditional put, regenerate on collision), hidden 128-bit nonce_secret, executor render,
subject_hash over the subject object, `challenge` leaf. WS-D calls issue_challenge() for CHG / CHG_REJECT.

Owner: WS-A.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Any

from executor import render as R
from executor.canonical import canonical_json
from executor.config import iso, now as clock
from executor.models import ChallengeRef
from executor.policy import rules
from executor.store import shims

NONCE_ATTEMPTS = 16
_PUBLIC = ("nonce", "purpose", "role", "subject_id", "deployment", "profile", "exp", "text", "text_sha256",
           "subject_hash", "used", "created_at")


def _jsonable(v: Any) -> Any:
    if isinstance(v, datetime):
        return iso(v)
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


def challenge_ref(row: dict[str, Any], *, full: bool = False) -> ChallengeRef:
    """Public view of a `nonces` row (never nonce_secret / params)."""
    pages = R.render_pages(row["text"], row["profile"])
    prof = R.get_profile(row["profile"])
    ref: dict[str, Any] = {k: row[k] for k in _PUBLIC if k in row and (full or k not in ("used", "created_at"))}
    ref.update(width=prof.width, lines_per_page=prof.lines_per_page, pages=len(pages),
               line_count=len(row["text"].split("\n")))
    return ref  # type: ignore[return-value]


def issue_challenge(*, purpose: str, role: str, subject_id: str, params: dict[str, Any], facts_digest: str | None,
                    store: Any, settings: Any, policy_hash: str | None = None, hints_digest: str | None = None,
                    inputs_digest: str | None = None, exp: datetime | None = None,
                    now: datetime | None = None) -> ChallengeRef:
    """Render `purpose` (= template) for `role` and persist the challenge. `params` = render kwargs without
    nonce/subject_hash/deployment/profile/width; for PAY pass exp=None and it is filled with the challenge exp."""
    now = now or clock(settings)
    exp = exp or now + timedelta(seconds=settings.challenge_ttl_seconds)
    policy_hash = policy_hash or rules.policy_hash()
    deployment = settings.deployment_id
    profile = settings.render_profile
    params = _jsonable(dict(params))
    if purpose != "VENDOR_ATTEST":
        params["role"] = role
    if purpose == "PAY":
        params["exp"] = iso(exp)
    for _ in range(NONCE_ATTEMPTS):
        nonce = secrets.token_hex(4).upper()
        nonce_secret = secrets.token_hex(16)
        subject = R.subject_object(deployment=deployment, purpose=purpose, role=role, subject_id=subject_id,
                                   nonce=nonce, params=params, facts_digest=facts_digest, policy_hash=policy_hash)
        sh = R.subject_hash(subject)
        kwargs = {**params, "nonce": nonce, "subject_hash": sh, "deployment": deployment}
        text = R.render(purpose, kwargs, profile=profile)
        row = {"nonce": nonce, "nonce_secret": nonce_secret, "purpose": purpose, "role": role,
               "subject_id": subject_id, "template": purpose, "params": canonical_json(kwargs).decode(),
               "subject": canonical_json(subject).decode(), "profile": profile, "deployment": deployment,
               "text": text, "text_sha256": R.text_sha256(text), "subject_hash": sh, "exp": iso(exp),
               "used": False, "created_at": iso(now)}
        if store.put_if_absent("nonces", row, "nonce"):
            break
    else:
        raise RuntimeError("could not allocate a unique displayed nonce")
    data = {"nonce": nonce, "nonce_secret_sha256": hashlib.sha256(nonce_secret.encode()).hexdigest(),
            "purpose": purpose, "role": role, "subject_id": subject_id, "deployment": deployment,
            "profile": profile, "text_sha256": row["text_sha256"], "subject_hash": sh, "exp": row["exp"],
            "template": purpose, "params": kwargs}
    shims.append(shims.make_event("challenge", data, subject_id=subject_id, actor="executor", settings=settings,
                                  policy_hash=policy_hash, inputs_digest=inputs_digest or shims.digest(kwargs),
                                  facts_digest=facts_digest or shims.digest([]),
                                  hints_digest=hints_digest or shims.digest([])),
                 store=store, settings=settings)
    return challenge_ref(row)


def load(nonce: str, *, store: Any) -> dict[str, Any] | None:
    return store.get("nonces", {"nonce": nonce})


def rerender(row: dict[str, Any]) -> tuple[str, str]:
    """(text, subject_hash) recomputed from the stored template/params/profile/subject (§4.3 step 3)."""
    text = R.render(row["template"], json.loads(row["params"]), profile=row["profile"])
    return text, R.subject_hash(json.loads(row["subject"]))
