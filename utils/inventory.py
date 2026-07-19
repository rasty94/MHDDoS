"""Asset inventory.

Promotes the thing being audited from an ad-hoc string into a first-class
asset (with group, tags, environment, owner and tenant) so the platform can
monitor a whole fleet on a schedule instead of one URL at a time.

Shares the SQLite database used by ``utils.storage`` so an asset and its audit
history live together.
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.storage import DEFAULT_DB_PATH, _connect

ASSET_TYPES = ("domain", "url", "host")


def init_inventory(db_path: str = DEFAULT_DB_PATH) -> None:
    with closing(_connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                asset_type TEXT NOT NULL DEFAULT 'domain',
                asset_group TEXT NOT NULL DEFAULT 'default',
                tags TEXT NOT NULL DEFAULT '[]',
                environment TEXT NOT NULL DEFAULT 'production',
                owner TEXT NOT NULL DEFAULT '',
                tenant TEXT NOT NULL DEFAULT 'default',
                created_at TEXT NOT NULL,
                UNIQUE (tenant, target)
            )
            """
        )
        conn.commit()


def add_asset(
    name: str,
    target: str,
    asset_type: str = "domain",
    group: str = "default",
    tags: Optional[List[str]] = None,
    environment: str = "production",
    owner: str = "",
    tenant: str = "default",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    if asset_type not in ASSET_TYPES:
        raise ValueError(f"asset_type must be one of {ASSET_TYPES}")
    init_inventory(db_path)
    created_at = datetime.now(timezone.utc).isoformat()
    with closing(_connect(db_path)) as conn:
        cursor = conn.execute(
            """
            INSERT INTO assets
                (name, target, asset_type, asset_group, tags, environment, owner, tenant, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant, target) DO UPDATE SET
                name=excluded.name,
                asset_type=excluded.asset_type,
                asset_group=excluded.asset_group,
                tags=excluded.tags,
                environment=excluded.environment,
                owner=excluded.owner
            """,
            (
                name,
                target,
                asset_type,
                group,
                json.dumps(tags or []),
                environment,
                owner,
                tenant,
                created_at,
            ),
        )
        conn.commit()
        return cursor.lastrowid or 0


def list_assets(
    tenant: Optional[str] = None, group: Optional[str] = None, db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    if not os.path.exists(db_path):
        return []
    init_inventory(db_path)
    query = "SELECT * FROM assets"
    clauses = []
    params: List[Any] = []
    if tenant is not None:
        clauses.append("tenant = ?")
        params.append(tenant)
    if group is not None:
        clauses.append("asset_group = ?")
        params.append(group)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY asset_group, name"
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_asset(row) for row in rows]


def get_asset(asset_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    if not os.path.exists(db_path):
        return None
    with closing(_connect(db_path)) as conn:
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return _row_to_asset(row) if row else None


def delete_asset(asset_id: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    if not os.path.exists(db_path):
        return False
    with closing(_connect(db_path)) as conn:
        cursor = conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
        return cursor.rowcount > 0


def _row_to_asset(row: sqlite3.Row) -> Dict[str, Any]:
    data = dict(row)
    data["tags"] = json.loads(data.get("tags") or "[]")
    return data
