"""Read-only check that every whitelisted value in agent-lb equals the source.

Compares source (SQLite, read-only) with target (Postgres) field by field and
prints only column names and match/mismatch. Never prints values. Tokens are
compared against the newest copy (source or vault) that the seed picked.

Run inside the agent-lb image: python /tools/verify_seed.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import psycopg  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

import seed  # noqa: E402
import vault  # noqa: E402


def normalize(value: object, kind: str) -> object:
    return seed.convert(value, kind)


def main() -> None:
    src = seed.open_source()
    data = seed.load_source(src)
    src.close()
    tokens = seed.choose_tokens(data["accounts"])
    problems: list[str] = []
    with psycopg.connect(seed.postgres_url(), row_factory=dict_row) as connection, connection.cursor() as cursor:
        connection.read_only = True

        def compare(table: str, key: str, source_rows, columns, overrides=None) -> None:
            types = seed.target_types(cursor, table)
            cursor.execute(f"SELECT * FROM {table}")
            target = {row[key]: row for row in cursor.fetchall()}
            if table != "dashboard_settings" and set(target) != {r[key] for r in source_rows}:
                problems.append(f"{table}: row set differs")
            for row in source_rows:
                other = target.get(row[key])
                if other is None:
                    problems.append(f"{table} {row[key]}: missing")
                    continue
                expected_row = {c: row[c] for c in columns}
                expected_row.update((overrides or {}).get(row[key], {}))
                for column, expected in expected_row.items():
                    got = other[column]
                    if isinstance(got, memoryview):
                        got = got.tobytes()
                    if hasattr(got, "tzinfo") and got.tzinfo is not None:
                        got = vault.parse_ts(got)
                    if normalize(expected, types[column]) != (str(got) if types[column] == "USER-DEFINED" else got):
                        problems.append(f"{table} {row[key]}: {column} mismatch")

        token_overrides = {
            account_id: {**{c: pick[c] for c in vault.TOKEN_COLUMNS}, "last_refresh": pick["last_refresh"]}
            for account_id, pick in tokens.items()
        }
        compare("accounts", "id", data["accounts"], seed.ACCOUNT_COPY, token_overrides)
        compare("api_keys", "id", data["keys"], seed.API_KEY_COPY)
        settings = dict(data["settings"])
        settings["id"] = 1
        compare(
            "dashboard_settings", "id", [settings], seed.SETTINGS_COPY,
            {1: {"password_hash": data["user"]["password_hash"], "totp_required_on_login": 0}},
        )
    if problems:
        for problem in problems:
            print(f"[verify] MISMATCH {problem}")
        raise SystemExit(1)
    print(
        f"[verify] OK: {len(data['accounts'])} accounts x {len(seed.ACCOUNT_COPY)} cols,"
        f" {len(data['keys'])} keys x {len(seed.API_KEY_COPY)} cols,"
        f" settings {len(seed.SETTINGS_COPY)} cols + password hash: all identical"
    )


if __name__ == "__main__":
    main()
