from __future__ import annotations
import sqlite3, json
from pathlib import Path
from typing import Any, Dict, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(
  job_id TEXT PRIMARY KEY,
  relay_id TEXT NOT NULL,
  action TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents(
  agent_id TEXT PRIMARY KEY,
  last_seen_at TEXT NOT NULL,
  platform TEXT,
  version TEXT,
  caps_json TEXT NOT NULL,
  logging_json TEXT NOT NULL
);
"""

class DB:
    def __init__(self, path: str = "./edge.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def upsert_job(self, *, job_id: str, relay_id: str, action: str, issued_at: str, expires_at: str,
                   payload: Dict[str, Any], signature: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO jobs VALUES (?,?,?,?,?,?,?)",
            (job_id, relay_id, action, issued_at, expires_at, json.dumps(payload), signature),
        )
        self.conn.commit()

    def list_jobs(self, relay_id: str, limit: int = 200):
        return self.conn.execute(
            "SELECT job_id,relay_id,action,issued_at,expires_at,payload,signature "
            "FROM jobs WHERE relay_id=? ORDER BY issued_at ASC LIMIT ?",
            (relay_id, limit),
        ).fetchall()

    def jobs_for_agent(self, relay_id: str, agent_id: str, limit: int = 10):
        rows = self.list_jobs(relay_id, limit=200)
        out = []
        for r in rows:
            payload = json.loads(r[5])
            targets = set(payload.get("targets") or [])
            if agent_id in targets:
                out.append(r)
            if len(out) >= limit:
                break
        return out

    def upsert_agent(self, *, agent_id: str, last_seen_at: str,
                     platform: Optional[str], version: Optional[str],
                     caps: Dict[str, Any], logging: Dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO agents(agent_id,last_seen_at,platform,version,caps_json,logging_json)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(agent_id) DO UPDATE SET
              last_seen_at=excluded.last_seen_at,
              platform=excluded.platform,
              version=excluded.version,
              caps_json=excluded.caps_json,
              logging_json=excluded.logging_json
            """,
            (agent_id, last_seen_at, platform, version, json.dumps(caps), json.dumps(logging)),
        )
        self.conn.commit()

    def agent_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(1) AS c FROM agents").fetchone()
        return int(row[0] or 0)
