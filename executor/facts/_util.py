"""Shared helpers for fact modules: Fact construction, snapshot loading and content hashes (prov). Owner: WS-D."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from executor.canonical import canonical_json
from executor.models import Fact

DISPLAY_WIDTH = 16  # safe3-mono-16x4 body width (CONTRACTS §2.1); <= every profile's width

# Snapshot name (FactSet.snapshots key, CONTRACTS §2.1) -> default path relative to the data dir.
SNAPSHOT_FILES: dict[str, str] = {
    "mostlyright": "mostlyright/snapshot.sqlite",
    "dns": "dns_snapshot.json",
    "adis": "adis_cache/adis.json",
    "bank_codes": "bank_codes.json",
    "vop": "vop_mock.json",
}


def make_fact(fid: str, severity: str, label: str, display_line: str, *, evidence: dict[str, Any] | None = None,
              prov: str | None = None) -> Fact:
    """F fact with a validated device line (printable ASCII, <= 18 chars). Fails closed on a bad line."""
    if not (len(display_line) <= DISPLAY_WIDTH and all(0x20 <= ord(c) <= 0x7E for c in display_line)):
        raise ValueError(f"{fid}: display_line {display_line!r} is not ASCII <= {DISPLAY_WIDTH}")
    f: Fact = {"id": fid, "kind": "F", "severity": severity, "label": label, "display_line": display_line}
    if evidence is not None:
        f["evidence"] = evidence
    if prov is not None:
        f["prov"] = prov
    return f


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest(obj: Any) -> str:
    """sha256(canonical_json(obj)) hex (CONTRACTS conventions)."""
    return sha256_hex(canonical_json(obj))


_FILE_CACHE: dict[tuple[str, int, int], tuple[bytes, str]] = {}


def read_snapshot(path: str | os.PathLike[str]) -> tuple[bytes, str]:
    """(raw bytes, sha256 hex) of a snapshot file, cached by (path, mtime, size)."""
    p = Path(path)
    st = p.stat()
    key = (str(p.resolve()), st.st_mtime_ns, st.st_size)
    hit = _FILE_CACHE.get(key)
    if hit is None:
        raw = p.read_bytes()
        hit = (raw, sha256_hex(raw))
        _FILE_CACHE[key] = hit
    return hit


def load_json(path: str | os.PathLike[str]) -> tuple[Any, str]:
    """(parsed JSON, sha256 hex of the raw bytes)."""
    raw, sha = read_snapshot(path)
    return json.loads(raw), sha


def data_dir(state: dict[str, Any] | None = None) -> Path:
    if state and state.get("data_dir"):
        return Path(state["data_dir"])
    return Path(os.environ.get("AIRGAP_DATA_DIR", "data"))


def snapshot_path(state: dict[str, Any] | None, name: str) -> Path:
    """state["snapshots"][name] if given, else <data_dir>/<SNAPSHOT_FILES[name]>."""
    snaps = (state or {}).get("snapshots") or {}
    if snaps.get(name):
        return Path(snaps[name])
    return data_dir(state) / SNAPSHOT_FILES[name]
