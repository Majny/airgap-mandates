"""F-VAT: ADIS unreliable-payer flag and published bank accounts for the DIČ. CONTRACTS.md v2 §2.1.

mode "cache" (default, tests and stage): data/adis_cache/adis.json
`{"as_of", "payers": {"CZ<ico>": {"unreliable": bool, "accounts": [IBAN, ...]}}}`; prov = its sha256.
mode "live" (opt-in, never in tests or on stage): the public ADIS SOAP service `rozhraniCRPDPH`,
operation getStatusNespolehlivyPlatceRozsireny, via zeep; prov = digest of the normalized response.
unreliable -> BLOCK 'VAT UNRELIABLE'; IBAN published -> INFO 'ADIS ACCT YES'; else WARN 'ADIS ACCT NO'. Owner: WS-D.
"""
from __future__ import annotations

import os
from typing import Any

from executor.facts import _util
from executor.facts.vop import norm_iban
from executor.models import Fact

LABEL = "Account published in VAT registry (ADIS)"
ADIS_WSDL = "https://adisrws.mfcr.cz/adistc/axis2/services/rozhraniCRPDPH.rozhraniCRPDPHSOAP?wsdl"
LIVE_TIMEOUT_S = 10


def dic(ico: str) -> str:
    s = "".join(str(ico).split()).upper()
    return s if s.startswith("CZ") else f"CZ{s}"


def cz_iban(bank: str, number: str, prefix: str = "") -> str:
    """Czech domestic account (prefix-number/bank) -> IBAN (mod-97 check digits)."""
    bban = f"{int(bank or 0):04d}{int(prefix or 0):06d}{int(number):010d}"
    check = 98 - int(bban + "123500") % 97  # "CZ00" -> C=12 Z=35 00
    return f"CZ{check:02d}{bban}"


def _live_lookup(dic_: str) -> dict[str, Any]:
    """Query ADIS for one DIČ; returns {"found", "unreliable", "accounts": [IBAN]}. Network; opt-in only."""
    import zeep  # noqa: PLC0415 - optional, only for live mode
    from zeep.transports import Transport  # noqa: PLC0415

    client = zeep.Client(ADIS_WSDL, transport=Transport(timeout=LIVE_TIMEOUT_S, operation_timeout=LIVE_TIMEOUT_S))
    return parse_live(client.service.getStatusNespolehlivyPlatceRozsireny([dic_.removeprefix("CZ")]))


def parse_live(resp: Any) -> dict[str, Any]:
    """Normalise a getStatusNespolehlivyPlatceRozsireny response (pure; tested with stand-in objects)."""
    rows = getattr(resp, "statusPlatceDPH", None) or []
    if not rows:
        return {"found": False, "unreliable": False, "accounts": []}
    row = rows[0]
    flag = str(getattr(row, "nespolehlivyPlatce", "NENALEZEN"))
    accounts: list[str] = []
    ucty = getattr(getattr(row, "zverejneneUcty", None), "ucet", None) or []
    for u in ucty:
        if getattr(u, "datumZverejneniUkonceni", None):
            continue  # publication of this account has ended
        std, nonstd = getattr(u, "standardniUcet", None), getattr(u, "nestandardniUcet", None)
        if std is not None:
            accounts.append(cz_iban(std.kodBanky, std.cislo, getattr(std, "predcisli", "") or ""))
        elif nonstd is not None and getattr(nonstd, "cislo", None):
            accounts.append(norm_iban(nonstd.cislo))
    return {"found": flag != "NENALEZEN", "unreliable": flag == "ANO", "accounts": sorted(accounts)}


def _from_cache(adis_path: str | os.PathLike[str], dic_: str) -> tuple[dict[str, Any] | None, str, str | None]:
    cache, sha = _util.load_json(adis_path)
    return (cache.get("payers") or {}).get(dic_), sha, cache.get("as_of")


def vat_fact(ico: str, iban: str, *, adis_path: str | os.PathLike[str], mode: str = "cache") -> Fact:
    """F-VAT for (ico, iban). Unknown DIČ counts as 'not published' (WARN), never as safe."""
    d, s = dic(ico), norm_iban(iban)
    if mode == "live":
        payer: dict[str, Any] | None = _live_lookup(d)
        prov, as_of, source = _util.digest({"dic": d, **payer}), None, "adis-live"
        if not payer["found"]:
            payer = None
    elif mode == "cache":
        payer, prov, as_of = _from_cache(adis_path, d)
        source = "adis-cache"
    else:
        raise ValueError(f"F-VAT mode must be cache|live, got {mode!r}")
    unreliable = bool(payer and payer.get("unreliable"))
    published = bool(payer) and s in {norm_iban(a) for a in payer.get("accounts") or []}
    evidence = {"dic": d, "payer_found": payer is not None, "unreliable": unreliable, "account_published": published,
                "as_of": as_of, "source": source}
    if unreliable:
        return _util.make_fact("F-VAT", "BLOCK", "VAT payer is listed as unreliable (ADIS)", "VAT UNRELIABLE",
                               evidence=evidence, prov=prov)
    if published:
        return _util.make_fact("F-VAT", "INFO", f"{LABEL}: yes", "ADIS ACCT YES", evidence=evidence, prov=prov)
    reason = "no" if payer else "no (DIČ not found)"
    return _util.make_fact("F-VAT", "WARN", f"{LABEL}: {reason}", "ADIS ACCT NO", evidence=evidence, prov=prov)
