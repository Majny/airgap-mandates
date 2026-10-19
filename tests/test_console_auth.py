"""Console access control (host/auth.py): OIDC sign-in via st.login/st.user, roles from env. Owner: WS-F."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from host import auth

OPS = auth.parse_list("alice@corp.example, @ap.corp.example")
AUD = auth.parse_list("audit.corp.example, bob@corp.example")


def test_parse_list_normalises():
    assert auth.parse_list(" A@X.cz, Y.CZ ,, @z.cz ") == ("a@x.cz", "y.cz", "z.cz")
    assert auth.parse_list(None) == () and auth.parse_list("") == ()


@pytest.mark.parametrize("email,role", [
    ("alice@corp.example", "operator"),
    ("ALICE@corp.example", "operator"),
    ("carol@ap.corp.example", "operator"),     # whole domain
    ("dave@audit.corp.example", "auditor"),
    ("bob@corp.example", "auditor"),           # exact email, the rest of corp.example is not listed
    ("eve@corp.example", None),
    ("eve@evil-audit.corp.example", None),     # no suffix matching
    ("eve@sub.audit.corp.example", None),      # a subdomain needs its own entry
    ("alice@corp.example@evil.example", None),
    ("", None),
    (None, None),
])
def test_role_for(email: str | None, role: str | None):
    assert auth.role_for(email, OPS, AUD) == role


def test_operator_wins_over_auditor():
    assert auth.role_for("x@both.example", ("both.example",), ("both.example",)) == "operator"


def test_tabs_per_role():
    assert auth.Identity("sso", "auditor", "a@b.c").tabs == ("Audit", "Reports")
    assert auth.Identity("sso", "auditor", "a@b.c").principal == "auditor"
    assert auth.Identity("local", "operator").tabs == auth.ALL_TABS
    assert auth.Identity("local", "operator").label == "local, no SSO"


def test_identify_fails_closed():
    env = {"AIRGAP_UI_OPERATORS": "corp.example"}
    assert auth.identify({"is_logged_in": True, "email": "a@corp.example"}, env).role == "operator"
    assert auth.identify({"is_logged_in": True, "email": "a@corp.example", "email_verified": False}, env) is None
    assert auth.identify({"is_logged_in": True, "email": "a@corp.example"}, {}) is None  # no lists: nobody


def test_provider_name():
    assert auth.provider_name({"client_id": "x", "redirect_uri": "u"}) is None
    assert auth.provider_name({"redirect_uri": "u", "cookie_secret": "s", "entra": {"client_id": "x"}}) == "entra"


class FakeSt:
    """Just enough of `streamlit` for auth.gate()."""

    def __init__(self, secrets: Any, user: dict[str, Any], click: bool = False) -> None:
        self.secrets, self.user, self.click = secrets, user, click
        self.session_state: dict[str, Any] = {}
        self.calls: list[tuple[str, Any]] = []

    def __getattr__(self, name: str) -> Any:
        return lambda *a, **k: self.calls.append((name, a[0] if a else k))

    def button(self, label: str, **_: Any) -> bool:
        self.calls.append(("button", label))
        return self.click

    def login(self, provider: str | None = None) -> None:
        self.calls.append(("login", provider))


class NoSecrets:
    def __contains__(self, key: str) -> bool:
        raise FileNotFoundError("no secrets.toml")


def test_gate_local_mode_without_auth_section():
    ident = auth.gate(FakeSt(NoSecrets(), {}), env={})
    assert ident == auth.Identity("local", "operator")


def test_gate_require_sso_refuses_local_mode():
    st = FakeSt({}, {})
    assert auth.gate(st, env={"AIRGAP_UI_REQUIRE_SSO": "1"}) is None
    assert any(c[0] == "error" for c in st.calls)


SECRETS = {"auth": {"redirect_uri": "https://console.corp.example/oauth2callback", "cookie_secret": "x",
                    "entra": {"client_id": "id", "client_secret": "s", "server_metadata_url": "https://idp/.well"}}}


def test_gate_signed_out_offers_login_only():
    st = FakeSt(SECRETS, {"is_logged_in": False}, click=True)
    assert auth.gate(st, env={"AIRGAP_UI_OPERATORS": "corp.example"}) is None
    assert ("login", "entra") in st.calls


def test_gate_signed_in_roles_and_access_line(capsys: pytest.CaptureFixture[str]):
    env = {"AIRGAP_UI_OPERATORS": "ops.example", "AIRGAP_UI_AUDITORS": "audit.example"}
    st = FakeSt(SECRETS, {"is_logged_in": True, "email": "Dana@Audit.example"})
    ident = auth.gate(st, env=env)
    assert ident == auth.Identity("sso", "auditor", "dana@audit.example")
    assert '"event": "console_access"' in capsys.readouterr().out
    auth.gate(st, env=env)  # once per session
    assert capsys.readouterr().out == ""
    st = FakeSt(SECRETS, {"is_logged_in": True, "email": "mallory@else.example"})
    assert auth.gate(st, env=env) is None
    assert any(c[0] == "error" and "not authorised" in c[1] for c in st.calls)


# ------------------------------------------------------------------ the real page (Streamlit AppTest)
st_testing = pytest.importorskip("streamlit.testing.v1")
UI_PATH = str(Path(auth.__file__).resolve().parent / "ui.py")


def test_page_with_auth_section_shows_only_sign_in(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "memory:")
    monkeypatch.setenv("AIRGAP_UI_REFRESH_S", "0")
    at = st_testing.AppTest.from_file(UI_PATH, default_timeout=60)
    at.secrets["auth"] = SECRETS["auth"]
    at.run()
    assert not at.exception
    assert [b.label for b in at.button] == ["Sign in with corporate SSO"]
    assert not at.tabs and not at.metric  # nothing from the executor reaches a signed-out browser


def test_page_local_mode_label(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:9")
    at = st_testing.AppTest.from_file(UI_PATH, default_timeout=30).run()
    assert any("local, no SSO" in m.value for m in at.markdown)


def _auditor_page() -> None:
    import streamlit as st

    from host import auth, ui
    ui.body(st, auth.Identity("sso", "auditor", "dana@audit.example"))


def test_auditor_sees_audit_and_reports_only(monkeypatch: pytest.MonkeyPatch):
    from host import ui

    seen: list[tuple[str, str]] = []

    def fake_call(method: str, path: str, body: Any, who: str) -> tuple[int, Any]:
        seen.append((path.split("?")[0], who))
        return (200, {"leaves": []}) if path.startswith("/audit/export") else (404, {"error": "not_found"})

    monkeypatch.setattr(ui, "_CALL", fake_call)
    at =st_testing.AppTest.from_function(_auditor_page, default_timeout=60).run()
    assert not at.exception
    assert [t.label for t in at.tabs] == ["Audit", "Reports"]
    assert not at.metric  # payment KPIs are operator-only
    assert seen and all(who == "auditor" for _, who in seen)  # read with the auditor principal only
    assert not {"/vendors", "/proposals", "/changes", "/ledger"} & {p for p, _ in seen}
