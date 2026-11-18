"""One-shot, idempotent seed: codex-lb-hardened (SQLite, read-only) -> agent-lb (Postgres).

Whitelist migration; every column is classified below and anything unexpected
fails loudly. See the workspace AGENTS.md ("In scope", "Seeding").

Never prints secrets: only counts, column names, account/key ids and decisions.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vault  # noqa: E402

SOURCE_DIR = Path(os.environ.get("SEED_SOURCE_DIR", "/source"))
SOURCE_DB = SOURCE_DIR / "store.db"
SOURCE_KEY = SOURCE_DIR / "encryption.key"
VAULT_DIR = Path(os.environ.get("TOKEN_VAULT_DIR", "/vault"))
TARGET_KEY = Path(os.environ["AGENT_LB_ENCRYPTION_KEY_FILE"])
DATA_DIR = Path(os.environ["AGENT_LB_DATA_DIR"])
MARKER_SCHEMA = "codex_gateway"

# --- §3 API keys -------------------------------------------------------------
API_KEY_COPY = (
    "id", "name", "key_hash", "key_prefix", "allowed_models", "enforced_model",
    "enforced_reasoning_effort", "enforced_service_tier", "apply_to_codex_model",
    "traffic_class", "account_assignment_scope_enabled", "expires_at", "is_active", "created_at",
)
API_KEY_SKIP = ("last_used_at",)  # history
API_KEY_MUST_BE = {  # codex-lb-only; dropped, so they must hold their default
    "usage_sections": "upstream_limits,account_pool_usage",
    "usage_share_percent": None,
    "source_assignment_scope_enabled": 0,
    "allowed_reasoning_efforts": None,
    "owner_user_id": None,
    "created_by_user_id": None,
    "transport_policy_override": None,
    "thread_cache_identity_override": None,
    "deactivated_reason": None,
}
API_KEY_EMPTY_TABLES = ("api_key_limits", "api_key_accounts", "api_key_model_sources")
API_KEY_PREFIX = "sk-clb-"

# --- §4 accounts -------------------------------------------------------------
ACCOUNT_COPY = (
    "id", "chatgpt_account_id", "email", "plan_type", "access_token_encrypted",
    "refresh_token_encrypted", "id_token_encrypted", "last_refresh", "created_at", "status",
    "deactivation_reason", "reset_at", "blocked_at", "limit_warmup_enabled", "alias",
    "routing_policy", "security_work_authorized", "workspace_id", "workspace_label", "seat_type",
)
ACCOUNT_DROP_FREE = ("codex_installation_id", "chatgpt_user_id")  # codex-lb seat identity
ACCOUNT_MUST_BE = {
    "delete_requested_at": None,
    "delete_history_requested": 0,
    "quota_limit_percent": None,
    "usage_limit_enabled": 0,
    "usage_limit_percent": None,
    "usage_limit_5h_percent": None,
    "usage_limit_weekly_percent": None,
}

# --- §5 routing / LB settings --------------------------------------------------
SETTINGS_COPY = (
    "routing_strategy", "sticky_threads_enabled", "prefer_earlier_reset_accounts",
    "prefer_earlier_reset_window", "relative_availability_power", "relative_availability_top_k",
    "sticky_reallocation_budget_threshold_pct", "sticky_reallocation_primary_budget_threshold_pct",
    "sticky_reallocation_secondary_budget_threshold_pct", "additional_quota_routing_policies_json",
    "openai_cache_affinity_max_age_seconds", "upstream_stream_transport",
    "http_responses_session_bridge_prompt_cache_idle_ttl_seconds",
    "http_responses_session_bridge_gateway_safe_mode", "single_account_id",
    "upstream_proxy_routing_enabled", "weekly_pace_working_days", "limit_warmup_enabled",
    "limit_warmup_windows", "limit_warmup_model", "limit_warmup_prompt",
    "limit_warmup_cooldown_seconds", "limit_warmup_min_available_percent", "warmup_model",
    "dashboard_session_ttl_seconds", "import_without_overwrite", "api_key_auth_enabled",
)
SETTINGS_SKIP = ("id", "created_at", "updated_at", "bootstrap_token_encrypted", "bootstrap_token_hash")
SETTINGS_MUST_BE = {"totp_required_on_login": 0, "upstream_proxy_default_pool_id": None}
# codex-lb-only settings with a non-default value: decided "drop all except retention".
SETTINGS_DECIDED = {
    "version": "dropped (codex-lb row-version counter)",
    "auto_redeem_reset_credits_before_expiry": "dropped (agent-lb env default already true)",
    "request_log_retention_days": "kept as the retention sidecar (--days 30)",
    "telemetry_consent": "dropped",
    "telemetry_instance_id": "dropped",
    "telemetry_private_key_encrypted": "dropped",
}
# codex-lb-only settings that must still hold their schema default.
SETTINGS_MUST_BE_DEFAULT = (
    "guest_access_enabled", "guest_password_hash", "http_downstream_transport_policy",
    "hide_upstream_quota_from_api_keys", "limit_warmup_staggered_idle_enabled",
    "limit_warmup_exhausted_threshold_percent", "weekly_pace_smoothing_minutes", "prohibit_fast_mode",
    "proxy_account_response_create_limit", "proxy_account_stream_limit",
    "proxy_account_stream_recovery_reserve", "limit_warmup_idle_threshold_percent",
    "show_reset_credit_badges", "show_reset_credit_expiry_badge", "usage_history_retention_days",
    "proxy_api_key_fair_share_congestion_threshold_pct", "soft_drain_enabled",
    "deterministic_failover_enabled", "circuit_breaker_enabled", "upstream_connect_timeout_seconds",
    "proxy_request_budget_seconds", "compact_request_budget_seconds",
    "transcription_request_budget_seconds", "stream_idle_timeout_seconds",
    "proxy_downstream_websocket_idle_timeout_seconds", "sse_keepalive_interval_seconds",
    "proxy_overload_isolation_seconds", "proxy_account_error_rate_weighting_enabled",
    "proxy_account_inflight_penalty_pct", "proxy_account_lease_token_weight",
    "proxy_account_lease_ttl_seconds", "http_responses_session_bridge_codex_prewarm_enabled",
    "http_responses_stream_request_budget_seconds",
    "http_responses_session_bridge_request_budget_seconds", "auth_guardian_enabled",
    "automations_scheduler_enabled", "rate_limit_reset_credits_refresh_enabled",
    "conversation_archive_enabled", "http_responses_session_bridge_operation_spool_retention_seconds",
    "guest_session_generation", "totp_required_for_admin_role", "local_login_policy",
    "thread_cache_identity_mode", "subagent_account_preference",
    "limit_warmup_reset_threshold_percent", "sticky_reallocation_timing",
)


class SeedError(SystemExit):
    pass


def log(message: str) -> None:
    print(f"[seed] {message}", flush=True)


def fail(message: str) -> None:
    raise SeedError(f"[seed] FAILED: {message}")


# --- source -------------------------------------------------------------------


def open_source() -> sqlite3.Connection:
    if not SOURCE_DB.is_file():
        fail(f"source DB not found at {SOURCE_DB}")
    connection = sqlite3.connect(f"file:{SOURCE_DB}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def source_columns(src: sqlite3.Connection, table: str) -> dict[str, str | None]:
    return {r["name"]: r["dflt_value"] for r in src.execute(f"SELECT name, dflt_value FROM pragma_table_info('{table}')")}


def classify(table: str, columns: dict[str, str | None], *groups: tuple | dict) -> None:
    known: set[str] = set()
    for group in groups:
        known.update(group)
    unknown = sorted(set(columns) - known)
    missing = sorted(known - set(columns))
    if unknown:
        fail(f"{table}: unclassified source columns {unknown}; update the whitelist first")
    if missing:
        fail(f"{table}: expected source columns are gone {missing}")


def same(value: object, expected: object) -> bool:
    if value is None or expected is None:
        return value is expected
    try:
        return float(value) == float(expected)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return str(value) == str(expected)


def schema_default(raw: str | None) -> object:
    if raw is None:
        return None
    text = raw.strip()
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1]
    if text.upper() == "NULL":
        return None
    return text


def check_must_be(table: str, rows: list[sqlite3.Row], expected: dict) -> None:
    for row in rows:
        for column, want in expected.items():
            if not same(row[column], want):
                fail(f"{table} row {row['id']}: {column} is no longer at its default; decide before migrating")


def load_source(src: sqlite3.Connection) -> dict:
    # §2 password
    users = src.execute("SELECT * FROM dashboard_users").fetchall()
    if len(users) != 1:
        fail(f"dashboard_users: expected exactly 1 user, found {len(users)}")
    user = users[0]
    if user["status"] != "active" or not (user["password_hash"] or "").startswith("$2"):
        fail("dashboard_users: the single user is not active with a bcrypt password hash")
    if user["totp_secret_encrypted"] is not None:
        fail("dashboard_users: TOTP is configured; agent-lb migration assumes none")

    # §3 API keys
    cols = source_columns(src, "api_keys")
    classify("api_keys", cols, API_KEY_COPY, API_KEY_SKIP, API_KEY_MUST_BE)
    keys = src.execute("SELECT * FROM api_keys ORDER BY created_at, id").fetchall()
    check_must_be("api_keys", keys, API_KEY_MUST_BE)
    for key in keys:
        if not key["key_prefix"].startswith(API_KEY_PREFIX):
            fail(f"api_keys row {key['id']}: prefix is not {API_KEY_PREFIX}; agent-lb would never accept it")
        if len(key["key_hash"]) != 64:
            fail(f"api_keys row {key['id']}: key_hash is not SHA-256 hex")
    for table in API_KEY_EMPTY_TABLES:
        count = src.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        if count:
            fail(f"{table}: has {count} rows; it is out of scope and must be empty")

    # §4 accounts
    cols = source_columns(src, "accounts")
    classify("accounts", cols, ACCOUNT_COPY, ACCOUNT_DROP_FREE, ACCOUNT_MUST_BE)
    accounts = src.execute("SELECT * FROM accounts ORDER BY created_at, id").fetchall()
    check_must_be("accounts", accounts, ACCOUNT_MUST_BE)

    # §5 settings
    cols = source_columns(src, "dashboard_settings")
    classify(
        "dashboard_settings", cols, SETTINGS_COPY, SETTINGS_SKIP, SETTINGS_MUST_BE,
        SETTINGS_DECIDED, SETTINGS_MUST_BE_DEFAULT,
    )
    settings_rows = src.execute("SELECT * FROM dashboard_settings").fetchall()
    if len(settings_rows) != 1:
        fail(f"dashboard_settings: expected exactly 1 row, found {len(settings_rows)}")
    settings = settings_rows[0]
    check_must_be("dashboard_settings", settings_rows, SETTINGS_MUST_BE)
    drifted = [c for c in SETTINGS_MUST_BE_DEFAULT if not same(settings[c], schema_default(cols[c]))]
    if drifted:
        fail(f"dashboard_settings: codex-lb-only settings no longer at default {drifted}; decide first")
    account_ids = {a["id"] for a in accounts}
    if settings["single_account_id"] is not None and settings["single_account_id"] not in account_ids:
        fail("dashboard_settings.single_account_id points at an account that is not migrated")

    return {"user": user, "keys": keys, "accounts": accounts, "settings": settings}


# --- tokens: newest of source vs vault -------------------------------------------


def choose_tokens(accounts: list[sqlite3.Row]) -> dict[str, dict]:
    records = vault.read_records(VAULT_DIR) if (VAULT_DIR / vault.RECORDS).exists() else []
    latest = vault.latest_by_account(records)
    chosen: dict[str, dict] = {}
    for account in accounts:
        source_blobs = {c: vault.as_bytes(account[c]) for c in vault.TOKEN_COLUMNS}
        source_refresh = vault.parse_ts(account["last_refresh"])
        pick = {"origin": "source", "last_refresh": source_refresh, **source_blobs}
        record = latest.get(account["id"])
        if record is not None and record["fingerprint"] != vault.fingerprint(source_blobs):
            vault_refresh = vault.parse_ts(record["last_refresh"])
            if vault_refresh >= source_refresh:
                pick = {"origin": f"vault ({record['origin']})", "last_refresh": vault_refresh, **vault.decode_blobs(record)}
        chosen[account["id"]] = pick
        log(f"account {account['id']}: tokens from {pick['origin']} (last_refresh {pick['last_refresh'].isoformat()})")
    for account_id in sorted(set(latest) - {a["id"] for a in accounts}):
        log(f"vault holds account {account_id}, which is not in the source; ignored (whitelist)")
    return chosen


# --- target ---------------------------------------------------------------------


def target_types(cursor, table: str) -> dict[str, str]:
    cursor.execute(
        "SELECT column_name, data_type FROM information_schema.columns"
        " WHERE table_schema = current_schema() AND table_name = %s",
        (table,),
    )
    rows = cursor.fetchall()
    types = {
        (r["column_name"] if isinstance(r, dict) else r[0]): (r["data_type"] if isinstance(r, dict) else r[1])
        for r in rows
    }
    if not types:
        fail(f"target table {table} does not exist after migrations")
    return types


def convert(value: object, kind: str) -> object:
    if value is None:
        return None
    if kind == "boolean":
        return bool(int(value))  # type: ignore[arg-type]
    if kind == "timestamp without time zone":
        return vault.parse_ts(value)
    if kind == "timestamp with time zone":
        return vault.parse_ts(value).replace(tzinfo=UTC)
    if kind == "bytea":
        return vault.as_bytes(value)
    if kind in ("integer", "bigint", "smallint"):
        return int(value)  # type: ignore[arg-type]
    if kind in ("double precision", "real", "numeric"):
        return float(value)  # type: ignore[arg-type]
    if isinstance(value, bytes):
        fail(f"refusing to store a binary value in a {kind} column")
    return value if isinstance(value, str) else str(value)


def insert(cursor, table: str, values: dict[str, object]) -> None:
    types = target_types(cursor, table)
    missing = sorted(set(values) - set(types))
    if missing:
        fail(f"target {table} lacks columns {missing}")
    columns = list(values)
    cursor.execute(
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(columns))})",
        [convert(values[c], types[c]) for c in columns],
    )


def update_settings(cursor, values: dict[str, object]) -> None:
    types = target_types(cursor, "dashboard_settings")
    missing = sorted(set(values) - set(types))
    if missing:
        fail(f"target dashboard_settings lacks columns {missing}")
    cursor.execute("SELECT count(*) FROM dashboard_settings")
    if cursor.fetchone()[0] == 0:
        insert(cursor, "dashboard_settings", {"id": 1, **values})
        return
    assignments = ", ".join(f"{c} = %s" for c in values)
    cursor.execute(
        f"UPDATE dashboard_settings SET {assignments}, updated_at = now() WHERE id = 1",
        [convert(values[c], types[c]) for c in values],
    )
    if cursor.rowcount != 1:
        fail("target dashboard_settings has no row id=1")


def postgres_url() -> str:
    return vault.postgres_url()


def already_seeded(cursor) -> bool:
    cursor.execute("SELECT to_regclass(%s)", (f"{MARKER_SCHEMA}.seed_marker",))
    if cursor.fetchone()[0] is None:
        return False
    cursor.execute(f"SELECT count(*) FROM {MARKER_SCHEMA}.seed_marker")
    return cursor.fetchone()[0] > 0


def ensure_key() -> None:
    """The agent-lb data dir must hold the source Fernet key (blobs copy verbatim)."""
    source_key = SOURCE_KEY.read_bytes().strip()
    if TARGET_KEY.exists():
        if TARGET_KEY.read_bytes().strip() != source_key:
            fail(f"{TARGET_KEY} differs from the source encryption.key; tokens would be unreadable")
        return
    TARGET_KEY.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(TARGET_KEY, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(source_key + b"\n")
    log(f"copied the source encryption.key to {TARGET_KEY}")


def main() -> None:
    import psycopg

    os.umask(0o077)
    ensure_key()

    with psycopg.connect(postgres_url(), autocommit=True) as connection, connection.cursor() as cursor:
        if already_seeded(cursor):
            log("target already seeded; nothing to do")
            return

    log("running agent-lb migrations")
    subprocess.run([sys.executable, "-m", "app.db.migrate", "upgrade"], check=True, cwd="/app")

    src = open_source()
    try:
        data = load_source(src)
    finally:
        src.close()
    tokens = choose_tokens(data["accounts"])
    settings = data["settings"]

    with psycopg.connect(postgres_url()) as connection:
        with connection.transaction(), connection.cursor() as cursor:
            for table in ("accounts", "api_keys", *API_KEY_EMPTY_TABLES):
                cursor.execute("SELECT to_regclass(%s)", (table,))
                if cursor.fetchone()[0] is None:
                    continue  # e.g. api_key_model_sources exists only in codex-lb
                cursor.execute(f"SELECT count(*) FROM {table}")
                if cursor.fetchone()[0]:
                    fail(f"target {table} is not empty but no seed marker exists; refusing to mix data")

            for account in data["accounts"]:
                values = {c: account[c] for c in ACCOUNT_COPY}
                pick = tokens[account["id"]]
                values.update({c: pick[c] for c in vault.TOKEN_COLUMNS})
                values["last_refresh"] = pick["last_refresh"]
                insert(cursor, "accounts", values)

            for key in data["keys"]:
                insert(cursor, "api_keys", {c: key[c] for c in API_KEY_COPY})

            values = {c: settings[c] for c in SETTINGS_COPY}
            values["password_hash"] = data["user"]["password_hash"]
            values["totp_required_on_login"] = 0
            update_settings(cursor, values)

            report = {
                "seeded_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "source": str(SOURCE_DB),
                "counts": {"accounts": len(data["accounts"]), "api_keys": len(data["keys"]), "dashboard_password": 1},
                "token_origin": {a: t["origin"] for a, t in tokens.items()},
                "settings_copied": list(SETTINGS_COPY),
                "codex_lb_only_settings": {
                    "decided": SETTINGS_DECIDED,
                    "verified_at_default": len(SETTINGS_MUST_BE_DEFAULT),
                },
            }
            cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {MARKER_SCHEMA}")
            cursor.execute(
                f"CREATE TABLE IF NOT EXISTS {MARKER_SCHEMA}.seed_marker"
                " (seeded_at timestamptz NOT NULL DEFAULT now(), report jsonb NOT NULL)"
            )
            cursor.execute(f"INSERT INTO {MARKER_SCHEMA}.seed_marker (report) VALUES (%s::jsonb)", (json.dumps(report),))

    report_path = DATA_DIR / "seed-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    log(
        f"seeded {report['counts']['accounts']} accounts, {report['counts']['api_keys']} API keys,"
        f" the dashboard password and {len(SETTINGS_COPY)} settings; report at {report_path}"
    )


if __name__ == "__main__":
    main()
