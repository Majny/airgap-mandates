"""AwsEnv: run WS-A's demo beats (executor.scenes / executor.e2e) against the deployed AWS stack. Owner: WS-F.

Same interface as `executor.scenes.DemoEnv` (call, tool, sign, at, nonces_for, active_mandate, store, settings,
clerk/treasury/stranger), so the scene functions run unmodified. Every action goes through the public API:
`infra.aws_e2e.signed_call` assumes the IAM role of the principal (airgap-host, airgap-tools, airgap-agent, ...) and
SigV4-signs the request, so the executor sees the real role ARN.

Two things differ from the in-process env and are said out loud on stage:
- the clock is real: `at(t)` waits until wall time reaches t (cooling-off is 20 s in the demo profile);
- `store` / `nonces_for` are READ-ONLY operator checks (DynamoDB with the operator's credentials) used by the scene
  assertions (R0 "no nonce exists", "ledger has no attacker IBAN"); they never write and never act for a principal.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from eth_account import Account

from executor.e2e import _sig

KEYS = Path(".local/aws_e2e_keys.json")
Call = Callable[[str, str, Any, str], tuple[int, Any]]


class AwsEnv:
    def __init__(self, url: str | None = None, *, call: Call | None = None, store: Any = None,
                 settings: Any = None, keys: dict[str, str] | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], datetime] | None = None) -> None:
        from executor.config import Settings

        self.settings = settings or Settings.from_env({**os.environ, "AIRGAP_BACKEND": "aws",
                                                       "AWS_REGION": "eu-central-1"})
        if call is None:
            from infra.aws_e2e import signed_call
            call = signed_call((url or self.settings.executor_url).rstrip("/"))
        self._call = call
        if store is None:
            from executor.store import get_store
            store = get_store(self.settings)
        self.store = _ReadOnly(store)
        keys = keys or json.loads(KEYS.read_text())  # written by `make demo-reset` (infra.aws_e2e.seed)
        self.clerk, self.treasury = Account.from_key(keys["clerk"]), Account.from_key(keys["treasury"])
        self.stranger = Account.create()
        self._sleep = sleep
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.step = 0

    @property
    def now(self) -> datetime:
        return self._clock()

    def at(self, t: datetime) -> None:
        wait = (t - self._clock()).total_seconds()
        if wait > 0:
            self._sleep(wait)

    def call(self, method: str, path: str, body: Any = None, who: str | None = None) -> tuple[int, Any]:
        return self._call(method, path, body, who or "host")

    def tool(self, name: str, args: dict | None = None) -> tuple[int, Any]:
        from executor.tools.manifest import manifest_sha256

        self.step += 1
        return self.call("POST", f"/tools/{name}", {"session_id": "ses_demo", "step": self.step,
                                                    "args": args or {}, "manifest_sha256": manifest_sha256()},
                         "agent")

    def sign(self, ch: dict, acct: Any, role: str | None = None) -> tuple[int, Any]:
        return self.call("POST", "/signatures", {"nonce": ch["nonce"], "role": role or ch["role"],
                                                 "sig": _sig(acct, ch["text"])}, "host")

    def nonces_for(self, subject_id: str) -> list[dict]:
        return [n for n in self.store.scan("nonces") if n.get("subject_id") == subject_id]

    def active_mandate(self) -> dict:
        until = (self.now + timedelta(days=1)).isoformat().replace("+00:00", "Z")
        st, r = self.call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                                "max_count": 20, "payee_scope": "existing_only",
                                                "valid_until": until, "currency": "CZK"}, "host")
        assert st == 201, r
        st, r = self.sign(r["challenge"], self.clerk)
        assert st == 200, r
        st, r = self.sign(r["challenge"], self.treasury)
        assert st == 200 and r["mandate"]["status"] == "ACTIVE", r
        return r["mandate"]


class _ReadOnly:
    """Store wrapper exposing reads only (scene assertions); any write raises."""

    _READS = ("get", "scan", "query")

    def __init__(self, store: Any) -> None:
        self._store = store

    def __getattr__(self, name: str) -> Any:
        if name not in self._READS:
            raise PermissionError(f"AwsEnv.store is read-only (operator check); {name!r} refused")
        return getattr(self._store, name)
