"""Seed helpers for dev/CI (memory/moto): canonical demo registry (CONTRACTS §1 hard rules) and enrolled signers.

The demo on AWS is seeded by tools/seed_data.py (WS-D) and tools/enroll.py (WS-C); this module only gives tests and
`make dev` the same canonical fictitious data. Owner: WS-A.
"""
from __future__ import annotations

from typing import Any

from executor.policy.mandate import REGISTRY_META, registry_snapshot

DEMO_VENDORS: list[dict[str, Any]] = [
    {"vendor_id": "ven_12345678", "ico": "12345678", "name": "ACME s.r.o.", "domain": "acme.cz",
     "iban": "CZ6508000000192000145399", "country": "CZ", "phone": "+420 200 000 001",
     "contact_email": "accounting@acme.cz", "registered_since": "2023-02-01", "in_network": True,
     "issuer_pins": [], "iban_history": [{"iban": "CZ6508000000192000145399", "from": "2024-03-01", "to": None,
                                          "change_id": None}]},
    {"vendor_id": "ven_87654321", "ico": "87654321", "name": "Beta Servis a.s.", "domain": "betaservis.cz",
     "iban": "CZ6203000000000123456789", "country": "CZ", "phone": "+420 200 000 002",
     "contact_email": "fakturace@betaservis.cz", "registered_since": "2022-06-15", "in_network": False,
     "issuer_pins": [], "iban_history": [{"iban": "CZ6203000000000123456789", "from": "2022-06-15", "to": None,
                                          "change_id": None}]},
]


def seed_registry(store: Any, vendors: list[dict[str, Any]] | None = None, version: int = 1) -> dict[str, Any]:
    for v in vendors if vendors is not None else DEMO_VENDORS:
        store.put("registry", dict(v))
    snap = registry_snapshot(store)
    store.put("registry", {**REGISTRY_META, "registry_version": version, "registry_hash": snap["hash"]})
    return snap


def enroll_signer(store: Any, address: str, role: str, *, device: str = "EMULATOR", label: str = "",
                  settings: Any = None) -> None:
    """Test/dev enrolment only (no ceremony, no attestation; labelled); the real one is tools/enroll.py (WS-C).
    Writes the enrolled_signers row and an `enroll` leaf (§7.2) so a full offline verify sees the signer."""
    from executor.config import Settings
    from executor.store import signers

    row = {"address": address.lower(), "role": role, "label": label or f"{role} (test key, no ceremony)",
           "device": device, "device_model": "T3T1", "firmware_version": "2.12.5", "cert_chain_sha256": None,
           "fw_hash": None, "derivation_path": "m/44'/60'/0'/0/0", "enroll_sig": "", "active": True,
           "enrolled_at": "2026-10-19T12:00:00Z"}
    signers.enroll(store, row, settings=settings or Settings(backend="memory"))


def seed_demo(store: Any) -> None:
    if store.get("registry", REGISTRY_META) is None:
        seed_registry(store)


_DEV_DATA_DIR: str | None = None


def dev_data_dir(base: str = "data") -> str:
    """Data dir for memory-backend runs: `base` if the MostlyRight snapshot has been built there, else a temp copy of
    `base` with a snapshot built from WS-D's synthetic fixture (tests/fixtures/mostlyright_sample.csv, fictitious
    names). Dev/CI only; never the demo."""
    global _DEV_DATA_DIR
    from pathlib import Path

    if (Path(base) / "mostlyright" / "snapshot.sqlite").exists():
        return base
    if _DEV_DATA_DIR is None:
        import shutil
        import tempfile

        from tools import load_mostlyright as loader

        root = Path(__file__).resolve().parents[2]
        d = Path(tempfile.mkdtemp(prefix="airgap-devdata-"))
        shutil.copytree(root / base, d, dirs_exist_ok=True, ignore=shutil.ignore_patterns("*.sqlite", "*.csv"))
        src = d / "mostlyright_fixture_2026-10-18.csv"
        shutil.copy(root / "tests" / "fixtures" / "mostlyright_sample.csv", src)
        loader.load(str(src), str(d / "mostlyright"))
        _DEV_DATA_DIR = str(d)
    return _DEV_DATA_DIR
