"""Settings from environment + executor clock. Owner: WS-A. Implements CONTRACTS.md §9 and §3 (table names)."""
from __future__ import annotations

import os
from dataclasses import dataclass, fields
from datetime import datetime, timezone

TABLES: list[str] = [
    "vendors",
    "mandates",
    "proposals",
    "changes",
    "attestations",
    "vendor_policies",
    "nonces",
    "ledger",
    "audit",
    "sth",
    "counters",
    "enrolled_signers",
    "inbox",
    "portal_notifications",
    "witness_state",
]


@dataclass(frozen=True)
class Settings:
    backend: str = "memory"  # AIRGAP_BACKEND: memory | moto | aws
    aws_region: str = "eu-central-1"  # AWS_REGION
    table_prefix: str = "airgap-"  # AIRGAP_TABLE_PREFIX
    inbox_bucket: str = "airgap-inbox"  # AIRGAP_INBOX_BUCKET
    anchor_bucket: str = "airgap-audit-anchor"  # AIRGAP_ANCHOR_BUCKET
    kms_key_id: str | None = None  # AIRGAP_KMS_KEY_ID
    witness_kms_key_id: str | None = None  # AIRGAP_WITNESS_KMS_KEY_ID
    witness_url: str = "inproc"  # AIRGAP_WITNESS_URL
    local_key_dir: str = ".local/keys"  # AIRGAP_LOCAL_KEY_DIR
    tsa_url: str = "https://freetsa.org/tsr"  # AIRGAP_TSA_URL ("off" disables)
    render_width: int = 32  # AIRGAP_RENDER_WIDTH
    tz: str = "Europe/Prague"  # AIRGAP_TZ
    challenge_ttl_seconds: int = 300  # AIRGAP_CHALLENGE_TTL_SECONDS
    cooling_seconds: int = 90  # AIRGAP_COOLING_SECONDS
    change_ttl_seconds: int = 3600  # AIRGAP_CHANGE_TTL_SECONDS
    callback_code_ttl_seconds: int = 600  # AIRGAP_CALLBACK_CODE_TTL_SECONDS
    sth_every_n_leaves: int = 10  # AIRGAP_STH_EVERY_N_LEAVES
    anchor_interval_seconds: int = 300  # AIRGAP_ANCHOR_INTERVAL_SECONDS
    data_dir: str = "data"  # AIRGAP_DATA_DIR
    adis_mode: str = "cache"  # AIRGAP_ADIS_MODE: cache | live
    fake_now: str | None = None  # AIRGAP_FAKE_NOW (ignored when backend == aws)
    executor_url: str = "http://127.0.0.1:8000"  # AIRGAP_EXECUTOR_URL
    bedrock_model_id: str = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"  # AIRGAP_BEDROCK_MODEL_ID (verify at runtime)
    qwen_base_url: str | None = None  # AIRGAP_QWEN_BASE_URL
    qwen_model: str | None = None  # AIRGAP_QWEN_MODEL
    trezor_path: str | None = None  # AIRGAP_TREZOR_PATH

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if env is None else env)
        mapping = {
            "backend": "AIRGAP_BACKEND",
            "aws_region": "AWS_REGION",
            "table_prefix": "AIRGAP_TABLE_PREFIX",
            "inbox_bucket": "AIRGAP_INBOX_BUCKET",
            "anchor_bucket": "AIRGAP_ANCHOR_BUCKET",
            "kms_key_id": "AIRGAP_KMS_KEY_ID",
            "witness_kms_key_id": "AIRGAP_WITNESS_KMS_KEY_ID",
            "witness_url": "AIRGAP_WITNESS_URL",
            "local_key_dir": "AIRGAP_LOCAL_KEY_DIR",
            "tsa_url": "AIRGAP_TSA_URL",
            "render_width": "AIRGAP_RENDER_WIDTH",
            "tz": "AIRGAP_TZ",
            "challenge_ttl_seconds": "AIRGAP_CHALLENGE_TTL_SECONDS",
            "cooling_seconds": "AIRGAP_COOLING_SECONDS",
            "change_ttl_seconds": "AIRGAP_CHANGE_TTL_SECONDS",
            "callback_code_ttl_seconds": "AIRGAP_CALLBACK_CODE_TTL_SECONDS",
            "sth_every_n_leaves": "AIRGAP_STH_EVERY_N_LEAVES",
            "anchor_interval_seconds": "AIRGAP_ANCHOR_INTERVAL_SECONDS",
            "data_dir": "AIRGAP_DATA_DIR",
            "adis_mode": "AIRGAP_ADIS_MODE",
            "fake_now": "AIRGAP_FAKE_NOW",
            "executor_url": "AIRGAP_EXECUTOR_URL",
            "bedrock_model_id": "AIRGAP_BEDROCK_MODEL_ID",
            "qwen_base_url": "AIRGAP_QWEN_BASE_URL",
            "qwen_model": "AIRGAP_QWEN_MODEL",
            "trezor_path": "AIRGAP_TREZOR_PATH",
        }
        kwargs: dict[str, object] = {}
        types = {f.name: f.type for f in fields(cls)}
        for attr, var in mapping.items():
            if var in env and env[var] != "":
                raw = env[var]
                kwargs[attr] = int(raw) if types[attr] in ("int", int) else raw
        return cls(**kwargs)  # type: ignore[arg-type]


def table_name(settings: Settings, name: str) -> str:
    """Physical DynamoDB table name, e.g. 'airgap-vendors'."""
    if name not in TABLES:
        raise KeyError(f"unknown table {name!r}")
    return f"{settings.table_prefix}{name}"


def now(settings: Settings) -> datetime:
    """Executor clock (tz-aware UTC). Honours AIRGAP_FAKE_NOW unless backend == 'aws'."""
    if settings.fake_now and settings.backend != "aws":
        dt = datetime.fromisoformat(settings.fake_now.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Format a tz-aware datetime as ISO 8601 UTC with 'Z' (CONTRACTS.md conventions)."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
