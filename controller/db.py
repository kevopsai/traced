from __future__ import annotations
import sqlite3, json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')


def utcnow_plus_seconds(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=int(seconds))).replace(microsecond=0).isoformat().replace('+00:00','Z')


SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  objective TEXT NOT NULL,
  tags TEXT NOT NULL,
  starts_at TEXT,
  ends_at TEXT,
  phase TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaign_objects(
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  object_type TEXT NOT NULL,
  name TEXT NOT NULL,
  cfg TEXT NOT NULL,
  tags TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs(
  job_id TEXT PRIMARY KEY,
  relay_id TEXT NOT NULL,
  action TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS correlations(
  correlation_id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  object_id TEXT NOT NULL,
  object_name TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_results(
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  relay_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  ok INTEGER NOT NULL,
  detail TEXT NOT NULL,
  metadata TEXT NOT NULL,
  finished_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  relay_id TEXT NOT NULL,
  correlation_id TEXT NOT NULL UNIQUE,
  provider TEXT NOT NULL,
  kind TEXT NOT NULL,
  provider_token_id TEXT NOT NULL,
  provider_url TEXT,
  download_name TEXT,
  created_at TEXT NOT NULL,
  last_hit_at TEXT,
  hit_count INTEGER NOT NULL DEFAULT 0,
  cfg_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS token_hits (
  id TEXT PRIMARY KEY,
  correlation_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_token_id TEXT NOT NULL,
  source_ip TEXT,
  user_agent TEXT,
  raw_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kv_state (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
  rule_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  state TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  scope TEXT NOT NULL,
  definition_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  campaign_id TEXT,
  deployment_id TEXT,
  relay_id TEXT,
  source_ip TEXT,
  action TEXT,
  body_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

CREATE TABLE IF NOT EXISTS rule_audit (
  id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  matched INTEGER NOT NULL,
  fired INTEGER NOT NULL,
  reason_json TEXT NOT NULL,
  actions_json TEXT NOT NULL,
  event_ref TEXT NOT NULL,
  campaign_id TEXT,
  provider_instance_id TEXT,
  source_ip TEXT
);

CREATE TABLE IF NOT EXISTS enroll_tokens (
  token TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  kind TEXT NOT NULL,
  config_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relays (
  relay_id TEXT PRIMARY KEY,
  label TEXT,
  last_seen_at TEXT,
  version TEXT,
  meta_json TEXT NOT NULL,
  agents_seen INTEGER NOT NULL DEFAULT 0,
  logging_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  relay_id TEXT,
  last_seen_at TEXT,
  platform TEXT,
  version TEXT,
  caps_json TEXT NOT NULL,
  logging_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaign_targets (
  campaign_id TEXT NOT NULL,
  relay_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  targeted_at TEXT NOT NULL,
  last_deploy_job_id TEXT,
  last_teardown_job_id TEXT,
  last_applied_at TEXT,
  last_status TEXT NOT NULL,
  last_detail TEXT,
  PRIMARY KEY (campaign_id, relay_id, agent_id)
);
"""


def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)

class DB:
    def __init__(self, path: str = "./controller.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        # lightweight migrations (additive)
        if not _has_column(self.conn, 'relays', 'label'):
            self.conn.execute('ALTER TABLE relays ADD COLUMN label TEXT')
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row

    # --- campaigns ---
    def create_campaign(self, *, id: str, name: str, objective: str, tags: List[str],
                        starts_at: Optional[str], ends_at: Optional[str], created_at: str):
        self.conn.execute(
            "INSERT INTO campaigns VALUES (?,?,?,?,?,?,?,?,?)",
            (id, name, objective, json.dumps(tags), starts_at, ends_at, "prepare", "draft", created_at),
        )
        self.conn.commit()

    def update_campaign_status(self, campaign_id: str, status: str):
        self.conn.execute("UPDATE campaigns SET status=? WHERE id=?", (status, campaign_id))
        self.conn.commit()

    def list_campaigns(self):
        return self.conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()

    def get_campaign(self, campaign_id: str):
        return self.conn.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()

    # --- objects ---
    def add_object(self, *, id: str, campaign_id: str, object_type: str, name: str,
                   cfg: Dict[str, Any], tags: List[str], created_at: str):
        self.conn.execute(
            "INSERT INTO campaign_objects VALUES (?,?,?,?,?,?,?)",
            (id, campaign_id, object_type, name, json.dumps(cfg), json.dumps(tags), created_at),
        )
        self.conn.commit()

    def list_objects(self, campaign_id: str):
        return self.conn.execute(
            "SELECT * FROM campaign_objects WHERE campaign_id=? ORDER BY created_at ASC",
            (campaign_id,),
        ).fetchall()

    # --- jobs ---
    def add_job(self, *, job_id: str, relay_id: str, action: str, issued_at: str, expires_at: str,
                payload: Dict[str, Any], signature: str):
        self.conn.execute(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?,?)",
            (job_id, relay_id, action, issued_at, expires_at, json.dumps(payload), signature),
        )
        self.conn.commit()

    def list_jobs_for_relay(self, relay_id: str, limit: int = 200):
        return self.conn.execute(
            "SELECT * FROM jobs WHERE relay_id=? ORDER BY issued_at ASC LIMIT ?",
            (relay_id, limit),
        ).fetchall()

    # --- correlations ---
    def upsert_correlation(self, *, correlation_id: str, campaign_id: str, object_id: str,
                          object_name: str, agent_id: str, created_at: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO correlations VALUES (?,?,?,?,?,?)",
            (correlation_id, campaign_id, object_id, object_name, agent_id, created_at),
        )
        self.conn.commit()

    # --- job results ---
    def add_job_result(self, *, id: str, job_id: str, relay_id: str, agent_id: str, ok: bool,
                       detail: str, metadata: Dict[str, Any], finished_at: str):
        self.conn.execute(
            "INSERT INTO job_results VALUES (?,?,?,?,?,?,?,?)",
            (id, job_id, relay_id, agent_id, 1 if ok else 0, detail, json.dumps(metadata), finished_at),
        )
        self.conn.commit()

    def latest_job_result_for_agent_campaign(self, campaign_id: str, agent_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            """
            SELECT jr.ok, jr.detail, jr.metadata, jr.finished_at
            FROM job_results jr
            JOIN jobs j ON j.job_id = jr.job_id
            WHERE jr.agent_id=? AND json_extract(j.payload, '$.campaign_ref')=?
            ORDER BY jr.finished_at DESC LIMIT 1
            """,
            (agent_id, campaign_id),
        ).fetchone()
        if not row:
            return None
        return {
            "ok": bool(row["ok"]),
            "detail": row["detail"],
            "metadata": json.loads(row["metadata"]),
            "finished_at": row["finished_at"],
        }

    # --- tokens ---
    def add_token(self, *, id: str, campaign_id: str, agent_id: str, relay_id: str, correlation_id: str,
                  provider: str, kind: str, provider_token_id: str, provider_url: Optional[str],
                  download_name: Optional[str], created_at: str, cfg_json: str):
        self.conn.execute(
            "INSERT INTO tokens(id,campaign_id,agent_id,relay_id,correlation_id,provider,kind,provider_token_id,provider_url,download_name,created_at,last_hit_at,hit_count,cfg_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,0,?)",
            (id, campaign_id, agent_id, relay_id, correlation_id, provider, kind, provider_token_id, provider_url, download_name, created_at, cfg_json),
        )
        self.conn.commit()

    def list_tokens(self, campaign_id: str):
        return self.conn.execute(
            "SELECT correlation_id,provider,kind,provider_token_id,provider_url,download_name,agent_id,relay_id,hit_count,last_hit_at,created_at "
            "FROM tokens WHERE campaign_id=? ORDER BY created_at ASC",
            (campaign_id,),
        ).fetchall()

    def get_token_by_provider_id(self, provider: str, provider_token_id: str):
        return self.conn.execute(
            "SELECT * FROM tokens WHERE provider=? AND provider_token_id=?",
            (provider, provider_token_id),
        ).fetchone()

    def record_token_hit(self, *, id: str, correlation_id: str, provider: str, provider_token_id: str,
                         source_ip: Optional[str], user_agent: Optional[str],
                         raw_json: Dict[str, Any], created_at: str):
        self.conn.execute(
            "INSERT INTO token_hits VALUES (?,?,?,?,?,?,?,?)",
            (id, correlation_id, provider, provider_token_id, source_ip, user_agent, json.dumps(raw_json), created_at),
        )
        self.conn.commit()

    def bump_token_hit(self, correlation_id: str, hit_at: str):
        self.conn.execute(
            "UPDATE tokens SET hit_count = hit_count + 1, last_hit_at=? WHERE correlation_id=?",
            (hit_at, correlation_id),
        )
        self.conn.commit()

    def token_hit_summary_for_campaign_agent(self, campaign_id: str, agent_id: str) -> Dict[str, Any]:
        row = self.conn.execute(
            """
            SELECT SUM(t.hit_count) AS c, MAX(t.last_hit_at) AS m
            FROM tokens t
            WHERE t.campaign_id=? AND t.agent_id=?
            """,
            (campaign_id, agent_id),
        ).fetchone()
        return {"count": int(row["c"] or 0), "last_hit_at": row["m"]}

    def campaign_status_summary(self, campaign_id: str) -> Dict[str, Any]:
        objects = self.conn.execute("SELECT COUNT(1) AS c FROM campaign_objects WHERE campaign_id=?", (campaign_id,)).fetchone()["c"]
        tokens = self.conn.execute("SELECT COUNT(1) AS c FROM tokens WHERE campaign_id=?", (campaign_id,)).fetchone()["c"]
        token_hits = self.conn.execute(
            "SELECT COUNT(1) AS c FROM token_hits th JOIN tokens t ON th.correlation_id=t.correlation_id WHERE t.campaign_id=?",
            (campaign_id,),
        ).fetchone()["c"]
        last_hit = self.conn.execute("SELECT MAX(last_hit_at) AS m FROM tokens WHERE campaign_id=?", (campaign_id,)).fetchone()["m"]
        return {"objects": objects, "tokens": tokens, "token_hits": token_hits, "last_hit_at": last_hit}

    # --- ops: relay + agent heartbeat ---
    def upsert_relay(self, *, relay_id: str, last_seen_at: str, version: Optional[str],
                     meta: Dict[str, Any], agents_seen: int, logging: Dict[str, Any]):
        self.conn.execute(
            """
            INSERT INTO relays(relay_id,label,last_seen_at,version,meta_json,agents_seen,logging_json)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(relay_id) DO UPDATE SET
              last_seen_at=excluded.last_seen_at,
              version=excluded.version,
              meta_json=excluded.meta_json,
              agents_seen=excluded.agents_seen,
              logging_json=excluded.logging_json,
              label=COALESCE(relays.label, excluded.label)
            """,
            (relay_id, None, last_seen_at, version, json.dumps(meta), int(agents_seen), json.dumps(logging)),
        )
        self.conn.commit()

    def upsert_agent(self, *, agent_id: str, relay_id: Optional[str], last_seen_at: str,
                     platform: Optional[str], version: Optional[str], caps: Dict[str, Any], logging: Dict[str, Any]):
        self.conn.execute(
            """
            INSERT INTO agents(agent_id,relay_id,last_seen_at,platform,version,caps_json,logging_json)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(agent_id) DO UPDATE SET
              relay_id=excluded.relay_id,
              last_seen_at=excluded.last_seen_at,
              platform=excluded.platform,
              version=excluded.version,
              caps_json=excluded.caps_json,
              logging_json=excluded.logging_json,
              label=COALESCE(relays.label, excluded.label)
            """,
            (agent_id, relay_id, last_seen_at, platform, version, json.dumps(caps), json.dumps(logging)),
        )
        self.conn.commit()

    def list_relays(self):
        return self.conn.execute("SELECT * FROM relays ORDER BY relay_id ASC").fetchall()

    def list_agents(self):
        return self.conn.execute("SELECT * FROM agents ORDER BY agent_id ASC").fetchall()

    def get_relay(self, relay_id: str):
        return self.conn.execute("SELECT * FROM relays WHERE relay_id=?", (relay_id,)).fetchone()


    def set_relay_label(self, relay_id: str, label: str | None) -> None:
        self.conn.execute("UPDATE relays SET label=? WHERE relay_id=?", (label, relay_id))
        self.conn.commit()

    def get_relay_label(self, relay_id: str) -> str | None:
        row = self.conn.execute("SELECT label FROM relays WHERE relay_id=?", (relay_id,)).fetchone()
        return row["label"] if row else None

    def list_agents_for_relay(self, relay_id: str):
        return self.conn.execute("SELECT * FROM agents WHERE relay_id=? ORDER BY agent_id ASC", (relay_id,)).fetchall()

    def get_agent(self, agent_id: str):
        return self.conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()

    # --- ops: campaign targets ---
    def upsert_campaign_targets(self, *, campaign_id: str, relay_id: str, agent_ids: List[str],
                               targeted_at: str, deploy_job_id: Optional[str], teardown_job_id: Optional[str],
                               status: str):
        for aid in agent_ids:
            self.conn.execute(
                """
                INSERT INTO campaign_targets(campaign_id,relay_id,agent_id,targeted_at,last_deploy_job_id,last_teardown_job_id,last_applied_at,last_status,last_detail)
                VALUES (?,?,?,?,?,?,NULL,?,NULL)
                ON CONFLICT(campaign_id,relay_id,agent_id) DO UPDATE SET
                  targeted_at=excluded.targeted_at,
                  last_deploy_job_id=COALESCE(excluded.last_deploy_job_id, campaign_targets.last_deploy_job_id),
                  last_teardown_job_id=COALESCE(excluded.last_teardown_job_id, campaign_targets.last_teardown_job_id),
                  last_status=excluded.last_status
                """,
                (campaign_id, relay_id, aid, targeted_at, deploy_job_id, teardown_job_id, status),
            )
        self.conn.commit()

    def mark_target_applied(self, *, campaign_id: str, agent_id: str, applied_at: str, status: str, detail: str):
        self.conn.execute(
            """
            UPDATE campaign_targets
            SET last_applied_at=?, last_status=?, last_detail=?
            WHERE campaign_id=? AND agent_id=?
            """,
            (applied_at, status, detail, campaign_id, agent_id),
        )
        self.conn.commit()

    def list_campaign_targets(self, campaign_id: str):
        return self.conn.execute(
            "SELECT * FROM campaign_targets WHERE campaign_id=? ORDER BY relay_id ASC, agent_id ASC",
            (campaign_id,),
        ).fetchall()


    def create_enroll_token(self, kind: str, expires_at: str, config: dict) -> str:
        token = secrets.token_urlsafe(24)
        now = utcnow()
        self.conn.execute(
            "INSERT INTO enroll_tokens(token,created_at,expires_at,used_at,kind,config_json) VALUES (?,?,?,?,?,?)",
            (token, now, expires_at, None, kind, json.dumps(config)),
        )
        self.conn.commit()
        return token

    def get_enroll_token(self, token: str):
        return self.conn.execute("SELECT * FROM enroll_tokens WHERE token=?", (token,)).fetchone()

    def mark_enroll_used(self, token: str) -> None:
        self.conn.execute("UPDATE enroll_tokens SET used_at=? WHERE token=?", (utcnow(), token))
        self.conn.commit()

    def is_enroll_valid(self, token: str, kind: str) -> tuple[bool, str, dict]:
        row = self.get_enroll_token(token)
        if not row:
            return False, "token not found", {}
        if row["kind"] != kind:
            return False, "wrong token kind", {}
        if row["used_at"]:
            return False, "token already used", {}
        # compare ISO strings lexicographically (same format)
        if utcnow() > row["expires_at"]:
            return False, "token expired", {}
        cfg = json.loads(row["config_json"] or "{}")
        return True, "ok", cfg


    # --- kv state (rate limits, dedupe, circuit breakers) ---
    def kv_get(self, key: str) -> dict | None:
        row = self.conn.execute("SELECT value_json, expires_at FROM kv_state WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        # expire if needed
        if utcnow() > row["expires_at"]:
            self.conn.execute("DELETE FROM kv_state WHERE key=?", (key,))
            self.conn.commit()
            return None
        return json.loads(row["value_json"] or "{}")

    def kv_set(self, key: str, value: dict, ttl_sec: int) -> None:
        expires_at = utcnow_plus_seconds(ttl_sec)
        self.conn.execute(
            "INSERT INTO kv_state(key,value_json,expires_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, expires_at=excluded.expires_at",
            (key, json.dumps(value), expires_at),
        )
        self.conn.commit()

    def kv_delete(self, key: str) -> None:
        self.conn.execute("DELETE FROM kv_state WHERE key=?", (key,))
        self.conn.commit()

    # --- rules ---
    def upsert_rule(self, *, rule_id: str, name: str, state: str, enabled: bool, scope: str, definition: dict, now: str) -> None:
        self.conn.execute(
            "INSERT INTO rules(rule_id,name,state,enabled,scope,definition_json,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(rule_id) DO UPDATE SET "
            "name=excluded.name, state=excluded.state, enabled=excluded.enabled, scope=excluded.scope, "
            "definition_json=excluded.definition_json, updated_at=excluded.updated_at",
            (rule_id, name, state, int(enabled), scope, json.dumps(definition), now, now),
        )
        self.conn.commit()

    def get_rule(self, rule_id: str):
        return self.conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone()

    def list_rules(self, state: str | None = None):
        if state:
            return self.conn.execute("SELECT * FROM rules WHERE state=? ORDER BY updated_at DESC", (state,)).fetchall()
        return self.conn.execute("SELECT * FROM rules ORDER BY updated_at DESC").fetchall()

    def set_rule_state(self, rule_id: str, state: str, enabled: bool, now: str) -> None:
        self.conn.execute("UPDATE rules SET state=?, enabled=?, updated_at=? WHERE rule_id=?", (state, int(enabled), now, rule_id))
        self.conn.commit()

    def insert_rule_audit(self, *, id: str, at: str, rule_id: str, matched: bool, fired: bool, reason: dict, actions: list, event_ref: str,
                          campaign_id: str | None, provider_instance_id: str | None, source_ip: str | None) -> None:
        self.conn.execute(
            "INSERT INTO rule_audit VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (id, at, rule_id, int(matched), int(fired), json.dumps(reason), json.dumps(actions), event_ref, campaign_id, provider_instance_id, source_ip),
        )
        self.conn.commit()

    def list_rule_audit(self, *, since: str | None = None, rule_id: str | None = None, campaign_id: str | None = None, limit: int = 200):
        q = "SELECT * FROM rule_audit WHERE 1=1"
        args: list = []
        if since:
            q += " AND at >= ?"
            args.append(since)
        if rule_id:
            q += " AND rule_id = ?"
            args.append(rule_id)
        if campaign_id:
            q += " AND campaign_id = ?"
            args.append(campaign_id)
        q += " ORDER BY at DESC LIMIT ?"
        args.append(int(limit))
        return self.conn.execute(q, tuple(args)).fetchall()


    def count_tokens_for_campaign_since(self, campaign_id: str, since_iso: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM tokens WHERE campaign_id=? AND created_at>=?",
            (campaign_id, since_iso),
        ).fetchone()
        return int(row["n"]) if row else 0


    def insert_event(self, kind: str, body: dict) -> str:
        eid = str(uuid.uuid4())
        ts = body.get("@timestamp") or utcnow()
        traced = body.get("traced") or {}
        campaign_id = traced.get("campaign_id")
        deployment_id = traced.get("deployment_id")
        relay_id = traced.get("relay_id") or traced.get("node_id")
        src_ip = (body.get("source") or {}).get("ip")
        action = (body.get("event") or {}).get("action")
        self.conn.execute(
            "INSERT INTO events(id,ts,kind,campaign_id,deployment_id,relay_id,source_ip,action,body_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (eid, ts, kind, campaign_id, deployment_id, relay_id, src_ip, action, json.dumps(body)),
        )
        self.conn.commit()
        return eid

    def list_events(self, kind: str | None = None, campaign_id: str | None = None, since: str | None = None, limit: int = 200):
        q = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if kind:
            q += " AND kind=?"; args.append(kind)
        if campaign_id:
            q += " AND campaign_id=?"; args.append(campaign_id)
        if since:
            q += " AND ts>=?"; args.append(since)
        q += " ORDER BY ts DESC LIMIT ?"; args.append(int(limit))
        return self.conn.execute(q, tuple(args)).fetchall()

    def purge_campaign(self, campaign_id: str, purge_events: bool = True) -> dict:
        # Best-effort cleanup across known tables; ignore missing relationships for MVP.
        out = {"campaign_id": campaign_id, "purged_events": 0, "purged_rule_state_keys": 0}
        if purge_events:
            cur = self.conn.execute("DELETE FROM events WHERE campaign_id=?", (campaign_id,))
            out["purged_events"] = cur.rowcount or 0
        # rule_state lives in kv_state for this MVP
        cur = self.conn.execute("SELECT key FROM kv_state WHERE key LIKE ?", (f"%|campaign={campaign_id}|%",))
        keys = [r[0] for r in cur.fetchall()]
        if keys:
            self.conn.executemany("DELETE FROM kv_state WHERE key=?", [(k,) for k in keys])
            out["purged_rule_state_keys"] = len(keys)
        self.conn.commit()
        return out

    def purge_events_older_than(self, cutoff_ts: str) -> int:
        cur = self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff_ts,))
        self.conn.commit()
        return cur.rowcount or 0
