"""Token vault: an append-only safe copy of the upstream account tokens.

Layout of the vault directory (0700; files 0600):
  encryption.key  copy of the Fernet key that protects every blob
  tokens.jsonl    one JSON record per account per token change (append-only)

Blobs are stored still encrypted (base64 of the Fernet ciphertext); nothing is
ever decrypted here. Nothing secret is ever printed: logs carry account ids,
fingerprints prefixes and timestamps only.

Usage:
  vault.py snapshot-sqlite <store.db> <key-file>   one-shot snapshot of a SQLite DB
  vault.py watch-postgres                          poll AGENT_LB_DATABASE_URL forever
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

VAULT_DIR = Path(os.environ.get("TOKEN_VAULT_DIR", "/vault"))
RECORDS = "tokens.jsonl"
KEY_FILE = "encryption.key"
TOKEN_COLUMNS = ("access_token_encrypted", "refresh_token_encrypted", "id_token_encrypted")
POLL_SECONDS = int(os.environ.get("TOKEN_VAULT_POLL_SECONDS", "30"))


def log(message: str) -> None:
    print(f"[token-vault] {datetime.now(UTC).isoformat(timespec='seconds')} {message}", flush=True)


def parse_ts(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def as_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)  # type: ignore[arg-type]


def fingerprint(blobs: dict[str, bytes | None]) -> str:
    digest = hashlib.sha256()
    for column in TOKEN_COLUMNS:
        blob = blobs[column]
        digest.update(column.encode())
        digest.update(b"\x00" if blob is None else b"\x01" + hashlib.sha256(blob).digest())
    return digest.hexdigest()


def ensure_vault_dir(vault: Path) -> None:
    vault.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(vault, 0o700)


def ensure_key(vault: Path, key_file: Path) -> None:
    """Copy the Fernet key into the vault; refuse a different key."""
    key = key_file.read_bytes().strip()
    target = vault / KEY_FILE
    if target.exists():
        if target.read_bytes().strip() != key:
            raise SystemExit(f"vault {KEY_FILE} differs from {key_file}; refusing (blobs would be unreadable)")
        return
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    log(f"copied {KEY_FILE} into the vault")


def read_records(vault: Path) -> list[dict]:
    path = vault / RECORDS
    if not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{number}: corrupt vault record ({exc.msg}); refusing") from exc
    return records


def latest_by_account(records: list[dict]) -> dict[str, dict]:
    """Newest record per account: highest last_refresh, then latest recorded_at."""
    latest: dict[str, dict] = {}
    for record in records:
        key = (parse_ts(record["last_refresh"]), record["recorded_at"])
        current = latest.get(record["account_id"])
        if current is None or key >= (parse_ts(current["last_refresh"]), current["recorded_at"]):
            latest[record["account_id"]] = record
    return latest


def decode_blobs(record: dict) -> dict[str, bytes | None]:
    return {c: None if record[c] is None else base64.b64decode(record[c]) for c in TOKEN_COLUMNS}


def append_record(vault: Path, record: dict) -> None:
    path = vault / RECORDS
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def capture(vault: Path, rows: list[dict], origin: str) -> int:
    """Append a record for every account whose tokens differ from the vault's newest copy."""
    latest = latest_by_account(read_records(vault))
    appended = 0
    for row in rows:
        account_id = row["id"]
        blobs = {c: as_bytes(row[c]) for c in TOKEN_COLUMNS}
        if blobs["access_token_encrypted"] is None or blobs["refresh_token_encrypted"] is None:
            log(f"account {account_id}: missing token blobs in {origin}; skipped")
            continue
        last_refresh = parse_ts(row["last_refresh"])
        fp = fingerprint(blobs)
        known = latest.get(account_id)
        if known is not None:
            if known["fingerprint"] == fp:
                continue
            if last_refresh < parse_ts(known["last_refresh"]):
                log(f"account {account_id}: {origin} copy is OLDER than the vault's; not recorded")
                continue
        record = {
            "v": 1,
            "recorded_at": datetime.now(UTC).isoformat(timespec="microseconds"),
            "origin": origin,
            "account_id": account_id,
            "chatgpt_account_id": row.get("chatgpt_account_id"),
            "email": row.get("email"),
            "last_refresh": last_refresh.isoformat(timespec="microseconds"),
            "fingerprint": fp,
            **{c: None if b is None else base64.b64encode(b).decode("ascii") for c, b in blobs.items()},
        }
        append_record(vault, record)
        latest[account_id] = record
        appended += 1
        log(f"account {account_id}: recorded tokens (last_refresh {record['last_refresh']}, fp {fp[:12]})")
    return appended


SELECT = "SELECT id, chatgpt_account_id, email, last_refresh, " + ", ".join(TOKEN_COLUMNS) + " FROM accounts"


def snapshot_sqlite(db_path: str, key_file: str) -> None:
    ensure_vault_dir(VAULT_DIR)
    ensure_key(VAULT_DIR, Path(key_file))
    uri = f"file:{Path(db_path).resolve()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = [dict(row) for row in connection.execute(SELECT)]
    finally:
        connection.close()
    appended = capture(VAULT_DIR, rows, f"sqlite:{Path(db_path).name}")
    log(f"snapshot done: {len(rows)} accounts, {appended} new records")


def postgres_url() -> str:
    url = os.environ["AGENT_LB_DATABASE_URL"]
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


def watch_postgres() -> None:
    import psycopg
    from psycopg.rows import dict_row

    ensure_vault_dir(VAULT_DIR)
    key_file = os.environ.get("AGENT_LB_ENCRYPTION_KEY_FILE")
    if key_file:
        ensure_key(VAULT_DIR, Path(key_file))
    log(f"watching agent-lb accounts every {POLL_SECONDS}s")
    while True:
        try:
            with psycopg.connect(postgres_url(), row_factory=dict_row, autocommit=False) as connection:
                connection.read_only = True
                with connection.cursor() as cursor:
                    cursor.execute(SELECT)
                    rows = cursor.fetchall()
                connection.rollback()
            capture(VAULT_DIR, rows, "postgres:agent-lb")
        except SystemExit:
            raise
        except Exception as exc:  # keep polling; never crash the sidecar on a transient error
            log(f"poll failed: {type(exc).__name__}")
        time.sleep(POLL_SECONDS)


def main(argv: list[str]) -> None:
    if len(argv) == 3 and argv[0] == "snapshot-sqlite":
        snapshot_sqlite(argv[1], argv[2])
    elif argv == ["watch-postgres"]:
        watch_postgres()
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    os.umask(0o077)
    main(sys.argv[1:])
