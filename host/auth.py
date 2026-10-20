"""Who may open the operations console, and which tabs they see. Owner: WS-F.

Sign-in is Streamlit's built-in OIDC (`st.login` / `st.user`), configured in `.streamlit/secrets.toml` `[auth]`
(sample: docs/BANK-READINESS.md, "Console sign-in"). Roles come from the environment, never from the identity
provider's free-form claims:

    AIRGAP_UI_OPERATORS = "alice@corp.example, ap-team.corp.example"   # emails or whole domains
    AIRGAP_UI_AUDITORS  = "audit.corp.example"

An operator sees every tab; an auditor sees Security, Audit and Reports only (all three read the audit export
alone). Anyone signed in but on neither list is refused (fail closed, also when both lists are empty). Without
`[auth]` the console runs in "local, no SSO" mode exactly as before (development, the stage laptop); `AIRGAP_UI_REQUIRE_SSO=1` (set in Dockerfile.console) refuses that mode.

Access control is a convenience wall, not the money wall: the console is an untrusted host (TB3). It holds no key
that moves money; payments still need the executor's policy and a Trezor signature.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Mapping

ALL_TABS = ("Overview", "Security", "Payments", "Payee changes", "Approvals", "Mandate", "Audit", "Reports")
TABS = {"operator": ALL_TABS, "auditor": ("Security", "Audit", "Reports")}


@dataclass(frozen=True)
class Identity:
    mode: str  # "local" (no SSO configured) | "sso"
    role: str  # "operator" | "auditor"
    email: str | None = None

    @property
    def tabs(self) -> tuple[str, ...]:
        return TABS[self.role]

    @property
    def principal(self) -> str:
        """Executor principal the console uses for this person: auditors read with the auditor role only."""
        return "auditor" if self.role == "auditor" else "host"

    @property
    def label(self) -> str:
        return "local, no SSO" if self.mode == "local" else f"{self.email} · {self.role}"


def parse_list(raw: str | None) -> tuple[str, ...]:
    """'a@x.cz, Y.CZ ,, @z.cz' -> ('a@x.cz', 'y.cz', 'z.cz'); a leading '@' marks a domain and is dropped."""
    out = []
    for item in (raw or "").split(","):
        item = item.strip().lower()
        if item.startswith("@"):
            item = item[1:]
        if item:
            out.append(item)
    return tuple(out)


def matches(email: str, entries: tuple[str, ...]) -> bool:
    """Exact email, or the email's domain equals an entry without '@'. No suffix tricks: 'evil-corp.example' does
    not match 'corp.example', and a subdomain needs its own entry."""
    email = email.strip().lower()
    if email.count("@") != 1:
        return False
    domain = email.split("@", 1)[1]
    return any(email == e if "@" in e else domain == e for e in entries)


def role_for(email: str | None, operators: tuple[str, ...], auditors: tuple[str, ...]) -> str | None:
    """Operator wins over auditor; None = not authorised."""
    if not email:
        return None
    if matches(email, operators):
        return "operator"
    if matches(email, auditors):
        return "auditor"
    return None


def sso_configured(secrets: Any) -> bool:
    try:
        return "auth" in secrets
    except Exception:  # noqa: BLE001 - no secrets.toml at all (StreamlitSecretNotFoundError, FileNotFoundError)
        return False


def provider_name(auth: Mapping[str, Any]) -> str | None:
    """st.login(provider): None when [auth] itself holds client_id, else the first [auth.<name>] table."""
    if "client_id" in auth:
        return None
    return next((k for k, v in auth.items() if isinstance(v, Mapping)), None)


def identify(user: Mapping[str, Any], env: Mapping[str, str] | None = None) -> Identity | None:
    """Identity for a signed-in OIDC user, or None. Refuses an email the provider marks unverified."""
    env = os.environ if env is None else env
    if user.get("email_verified") is False:
        return None
    email = user.get("email")
    role = role_for(email, parse_list(env.get("AIRGAP_UI_OPERATORS")), parse_list(env.get("AIRGAP_UI_AUDITORS")))
    return Identity("sso", role, str(email).lower()) if role else None


def access_event(ident: Identity) -> str:
    """One JSON line per console session on stdout, for the bank's log shipping (who opened what, with which role).
    The executor's own audit log is the record of money; this is the record of console access."""
    return json.dumps({"event": "console_access", "mode": ident.mode, "email": ident.email, "role": ident.role,
                       "tabs": list(ident.tabs)}, sort_keys=True)


def gate(st: Any, env: Mapping[str, str] | None = None) -> Identity | None:
    """Run at the top of the page. Returns the identity, or renders the sign-in / refusal page and returns None
    (the caller stops). Without [auth] -> local operator, unless AIRGAP_UI_REQUIRE_SSO=1."""
    env = os.environ if env is None else env
    if not sso_configured(st.secrets):
        if env.get("AIRGAP_UI_REQUIRE_SSO") == "1":
            st.error("This console requires corporate sign-in, but no [auth] section is configured in "
                     ".streamlit/secrets.toml. Refusing to start in local mode.")
            return None
        return Identity("local", "operator")
    user = st.user
    if not user.get("is_logged_in"):
        st.markdown("## AirGap Mandates  \nPayment control for AI agents")
        st.info("Sign in with your corporate account to open the operations console.")
        if st.button("Sign in with corporate SSO", type="primary"):
            st.login(provider_name(st.secrets["auth"]))
        return None
    ident = identify(user, env)
    if ident is None:
        st.error(f"Signed in as {user.get('email') or 'an account without an email'}, which is not authorised for "
                 "this console. Ask the console owner to add you to AIRGAP_UI_OPERATORS or AIRGAP_UI_AUDITORS.")
        if st.button("Sign out"):
            st.logout()
        return None
    if not st.session_state.get("_airgap_access_logged"):
        st.session_state["_airgap_access_logged"] = True
        print(access_event(ident), file=sys.stdout, flush=True)
    return ident
