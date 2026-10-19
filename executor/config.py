"""Settings from environment + executor clock. Owner: WS-A. Implements CONTRACTS.md v2 §9 and §3 (tables).

AWS is mandatory for the demo: every trusted component runs on AWS eu-central-1 with AIRGAP_BACKEND=aws.
The memory/moto backends are for development and CI only (assert_demo_ready()).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, fields
from datetime import datetime, timezone

# Physical tables (CONTRACTS §3.1): separate IAM resources + single-table `main` + portal-only `portal`.
PHYSICAL_TABLES: list[str] = ["ledger", "mandates", "audit", "registry", "witness_state", "main", "portal"]

# Logical table (entity) name -> physical table. The Store API always takes logical names.
LOGICAL_TABLES: dict[str, str] = {
    "ledger": "ledger",
    "mandates": "mandates",
    "audit": "audit",
    "registry": "registry",
    "witness_state": "witness_state",
    "proposals": "main",
    "changes": "main",
    "attestations": "main",
    "vendor_policies": "main",
    "nonces": "main",
    "counters": "main",
    "enrolled_signers": "main",
    "inbox": "main",
    "checkpoints": "main",
    "tool_calls": "main",
    "portal_notifications": "portal",
}

# pk prefix of each entity stored in `main` (pk = "<prefix>#<id>").
MAIN_PK_PREFIX: dict[str, str] = {
    "proposals": "proposal",
    "changes": "change",
    "attestations": "attestation",
    "vendor_policies": "vendor_policy",
    "nonces": "nonce",
    "counters": "counter",
    "enrolled_signers": "signer",
    "inbox": "email",
    "checkpoints": "checkpoint",
    "tool_calls": "toolsession",
}

# Back-compat alias: logical names.
TABLES: list[str] = list(LOGICAL_TABLES)


@dataclass(frozen=True)
class Settings:
    backend: str = "memory"  # AIRGAP_BACKEND: memory (dev) | moto (CI) | aws (the demo)
    demo_profile: str = "demo"  # AIRGAP_DEMO_PROFILE: demo | prod
    deployment_id: str = "DEMO"  # AIRGAP_DEPLOYMENT_ID (1-5 chars [A-Z0-9])
    aws_region: str = "eu-central-1"  # AWS_REGION
    table_prefix: str = "airgap-"  # AIRGAP_TABLE_PREFIX
    inbox_bucket: str = "airgap-inbox"  # AIRGAP_INBOX_BUCKET
    anchor_bucket: str = "airgap-log"  # AIRGAP_ANCHOR_BUCKET (Object Lock GOVERNANCE, 1 day)
    kms_key_id: str | None = None  # AIRGAP_KMS_KEY_ID (Ed25519 log key)
    witness_kms_key_id: str | None = None  # AIRGAP_WITNESS_KMS_KEY_ID (Ed25519 W1 key)
    witness_url: str = "inproc"  # AIRGAP_WITNESS_URL (W1)
    w2_url: str = "off"  # AIRGAP_W2_URL (litewitness relay)
    log_origin: str = "airgap.example/demo"  # AIRGAP_LOG_ORIGIN (origin = <log_origin>/<log_id>)
    local_key_dir: str = ".local/keys"  # AIRGAP_LOCAL_KEY_DIR
    tsa_url: str = "off"  # AIRGAP_TSA_URL ("off" disables RFC 3161)
    render_profile: str = "safe5-mono-18x7"  # AIRGAP_RENDER_PROFILE
    tz: str = "Europe/Prague"  # AIRGAP_TZ
    challenge_ttl_seconds: int = 300  # AIRGAP_CHALLENGE_TTL_SECONDS
    cooling_seconds: int = 20  # AIRGAP_COOLING_SECONDS (demo; prod 86400)
    break_glass_cooling_seconds: int = 20  # AIRGAP_BREAK_GLASS_COOLING_SECONDS (demo; prod 259200)
    change_ttl_seconds: int = 3600  # AIRGAP_CHANGE_TTL_SECONDS
    callback_code_ttl_seconds: int = 600  # AIRGAP_CALLBACK_CODE_TTL_SECONDS
    checkpoint_every_n_leaves: int = 10  # AIRGAP_CHECKPOINT_EVERY_N_LEAVES
    checkpoint_max_seconds: int = 30  # AIRGAP_CHECKPOINT_MAX_SECONDS
    anchor_interval_seconds: int = 300  # AIRGAP_ANCHOR_INTERVAL_SECONDS
    mandate_dual_threshold_minor: int = 10_000_000  # AIRGAP_MANDATE_DUAL_THRESHOLD_MINOR (100000 CZK)
    data_dir: str = "data"  # AIRGAP_DATA_DIR
    adis_mode: str = "cache"  # AIRGAP_ADIS_MODE: cache | live
    fake_now: str | None = None  # AIRGAP_FAKE_NOW (ignored when backend == aws)
    executor_url: str = "http://127.0.0.1:8000"  # AIRGAP_EXECUTOR_URL
    bedrock_model_id: str = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"  # AIRGAP_BEDROCK_MODEL_ID (verify at runtime)
    qwen_model: str = "qwen.qwen3-235b-a22b-2507-v1:0"  # AIRGAP_QWEN_MODEL
    qwen_base_url: str | None = None  # AIRGAP_QWEN_BASE_URL
    sonnet_budget: int = 50  # AIRGAP_SONNET_BUDGET (requests/min, team-wide)
    agent_mode: str = "quarantined"  # AGENT_MODE: naive | quarantined
    gateway: str = "local"  # AIRGAP_GATEWAY: agentcore | local
    trezor_path: str | None = None  # AIRGAP_TREZOR_PATH

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if env is None else env)
        kwargs: dict[str, object] = {}
        types = {f.name: f.type for f in fields(cls)}
        for attr, var in ENV_VARS.items():
            if var in env and env[var] != "":
                raw = env[var]
                kwargs[attr] = int(raw) if types[attr] in ("int", int) else raw
        return cls(**kwargs)  # type: ignore[arg-type]


ENV_VARS: dict[str, str] = {
    "backend": "AIRGAP_BACKEND",
    "demo_profile": "AIRGAP_DEMO_PROFILE",
    "deployment_id": "AIRGAP_DEPLOYMENT_ID",
    "aws_region": "AWS_REGION",
    "table_prefix": "AIRGAP_TABLE_PREFIX",
    "inbox_bucket": "AIRGAP_INBOX_BUCKET",
    "anchor_bucket": "AIRGAP_ANCHOR_BUCKET",
    "kms_key_id": "AIRGAP_KMS_KEY_ID",
    "witness_kms_key_id": "AIRGAP_WITNESS_KMS_KEY_ID",
    "witness_url": "AIRGAP_WITNESS_URL",
    "w2_url": "AIRGAP_W2_URL",
    "log_origin": "AIRGAP_LOG_ORIGIN",
    "local_key_dir": "AIRGAP_LOCAL_KEY_DIR",
    "tsa_url": "AIRGAP_TSA_URL",
    "render_profile": "AIRGAP_RENDER_PROFILE",
    "tz": "AIRGAP_TZ",
    "challenge_ttl_seconds": "AIRGAP_CHALLENGE_TTL_SECONDS",
    "cooling_seconds": "AIRGAP_COOLING_SECONDS",
    "break_glass_cooling_seconds": "AIRGAP_BREAK_GLASS_COOLING_SECONDS",
    "change_ttl_seconds": "AIRGAP_CHANGE_TTL_SECONDS",
    "callback_code_ttl_seconds": "AIRGAP_CALLBACK_CODE_TTL_SECONDS",
    "checkpoint_every_n_leaves": "AIRGAP_CHECKPOINT_EVERY_N_LEAVES",
    "checkpoint_max_seconds": "AIRGAP_CHECKPOINT_MAX_SECONDS",
    "anchor_interval_seconds": "AIRGAP_ANCHOR_INTERVAL_SECONDS",
    "mandate_dual_threshold_minor": "AIRGAP_MANDATE_DUAL_THRESHOLD_MINOR",
    "data_dir": "AIRGAP_DATA_DIR",
    "adis_mode": "AIRGAP_ADIS_MODE",
    "fake_now": "AIRGAP_FAKE_NOW",
    "executor_url": "AIRGAP_EXECUTOR_URL",
    "bedrock_model_id": "AIRGAP_BEDROCK_MODEL_ID",
    "qwen_model": "AIRGAP_QWEN_MODEL",
    "qwen_base_url": "AIRGAP_QWEN_BASE_URL",
    "sonnet_budget": "AIRGAP_SONNET_BUDGET",
    "agent_mode": "AGENT_MODE",
    "gateway": "AIRGAP_GATEWAY",
    "trezor_path": "AIRGAP_TREZOR_PATH",
}


class DemoNotReady(RuntimeError):
    """Raised when a demo scene is started on anything but the AWS backend in eu-central-1."""


def assert_demo_ready(settings: Settings) -> None:
    """The demo runs on AWS only (CONTRACTS §9). memory/moto are for development and CI."""
    if settings.backend != "aws" or settings.aws_region != "eu-central-1":
        raise DemoNotReady(
            f"demo requires AIRGAP_BACKEND=aws in eu-central-1 (got backend={settings.backend!r}, "
            f"region={settings.aws_region!r}); memory/moto are development/CI only"
        )


def physical_table(settings: Settings, logical: str) -> str:
    """Physical DynamoDB table for a logical table name, e.g. 'proposals' -> 'airgap-main'."""
    if logical not in LOGICAL_TABLES:
        raise KeyError(f"unknown table {logical!r}")
    return f"{settings.table_prefix}{LOGICAL_TABLES[logical]}"


def table_name(settings: Settings, name: str) -> str:
    """Alias of physical_table (v1 name)."""
    return physical_table(settings, name)


def log_origin(settings: Settings, log_id: str = "audit") -> str:
    """Checkpoint origin line, e.g. 'airgap.example/demo/audit'."""
    return f"{settings.log_origin}/{log_id}"


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
