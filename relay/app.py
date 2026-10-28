from __future__ import annotations
import os, json, datetime, threading, time
import requests
from fastapi import FastAPI, Header, Depends, HTTPException
from relay.db import DB
from relay.models import JobEnvelope, AgentCheckin, AgentJobResult, AgentLog
from relay.signing import verify
from relay.telemetry import SyslogForwarder

RELAY_ID = os.environ.get("EDGE_RELAY_ID", "relay-1")
DB_PATH = os.environ.get("EDGE_DB", "./edge.db")

CORE_URL = os.environ.get("CORE_URL", "http://127.0.0.1:8443")
SHARED_SECRET = os.environ.get("EDGE_SHARED_SECRET", "change-me").encode("utf-8")

EDGE_API_KEY = os.environ.get("EDGE_API_KEY", "")
EDGE_API_KEY_PREV = os.environ.get("EDGE_API_KEY_PREV", "")

SO_HOST = os.environ.get("EDGE_SO_HOST", "127.0.0.1")
SO_PORT = int(os.environ.get("EDGE_SO_PORT", "514"))
SO_PROTO = os.environ.get("EDGE_SO_PROTO", "udp")

POLL_ENABLED = os.environ.get("EDGE_POLL_ENABLED", "true").lower() in ("1", "true", "yes")

DASHBOARD_WEBHOOK_URL = os.environ.get("DASHBOARD_WEBHOOK_URL", "")
DASHBOARD_WEBHOOK_SECRET = os.environ.get("DASHBOARD_WEBHOOK_SECRET", "")

def _push_dashboard(payload: dict) -> None:
    """Fire-and-forget push to Base44 dashboard webhook."""
    if not DASHBOARD_WEBHOOK_URL or not DASHBOARD_WEBHOOK_SECRET:
        return
    import threading, urllib.request as _urllib, urllib.error
    def _send():
        try:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            req = _urllib.Request(
                DASHBOARD_WEBHOOK_URL, data=body,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {DASHBOARD_WEBHOOK_SECRET}"},
                method="POST",
            )
            _urllib.urlopen(req, timeout=5)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()
POLL_SECONDS = int(os.environ.get("EDGE_POLL_SECONDS", "30"))

RELAY_VERSION = os.environ.get("EDGE_VERSION", "0.6.0")
EDGE_STATE_DIR = os.environ.get("EDGE_STATE_DIR", "/var/lib/edge/state")

db = DB(DB_PATH)
syslog = SyslogForwarder(SO_HOST, SO_PORT, SO_PROTO)

_last_so_send_at: str | None = None
_last_so_send_ok: bool | None = None

app = FastAPI(title="Edge Relay", version=RELAY_VERSION)

def _bearer_token(authorization: str | None) -> str:
    if not authorization:
        return ""
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()

def require_edge_key(authorization: str | None = Header(default=None)) -> None:
    token = _bearer_token(authorization)
    allowed = {k for k in (EDGE_API_KEY, EDGE_API_KEY_PREV) if k}
    if not allowed:
        raise HTTPException(503, "auth_not_configured")
    if token not in allowed:
        raise HTTPException(401, "unauthorized")

def _auth_header() -> dict:
    if not EDGE_API_KEY:
        return {}
    return {"Authorization": f"Bearer {EDGE_API_KEY}"}

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _apply_put_state(job: dict) -> tuple[bool, str]:
    # Write provider adaptation state locally so provider wrappers can poll it.
    try:
        payload = job.get('payload') or {}
        provider_instance_id = payload.get('provider_instance_id') or payload.get('pi') or 'unknown'
        state = payload.get('state') if isinstance(payload.get('state'), dict) else payload
        os.makedirs(EDGE_STATE_DIR, exist_ok=True)
        path = os.path.join(EDGE_STATE_DIR, f"{provider_instance_id}.json")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(state, f, separators=(',', ':'), sort_keys=True)
        return True, path
    except Exception as e:
        return False, str(e)

def _relay_checkin() -> None:
    payload = {
        "version": RELAY_VERSION,
        "meta": {"relay_id": RELAY_ID, "hostname": os.environ.get("EDGE_META_HOSTNAME",""), "model": os.environ.get("EDGE_META_MODEL",""), "serial": os.environ.get("EDGE_META_SERIAL",""), "arch": os.environ.get("EDGE_META_ARCH","")},
        "agents_seen": db.agent_count(),
        "logging": {
            "so_host": SO_HOST,
            "so_port": SO_PORT,
            "so_proto": SO_PROTO,
            "last_send_at": _last_so_send_at,
            "last_send_ok": _last_so_send_ok,
        },
    }
    r = requests.post(
        f"{CORE_URL}/v1/relays/{RELAY_ID}/checkin",
        headers=_auth_header(),
        json=payload,
        timeout=15,
    )
    r.raise_for_status()
    jobs = r.json()

    _push_dashboard({
        "type": "status_update",
        "relays": [{"relay_id": RELAY_ID, "status": "ok", "last_seen": _now_iso(), "agent_count": db.agent_count()}],
        "agents": [],
    })

    for job in jobs:
        env = {
            "relay_id": job["relay_id"],
            "action": job["action"],
            "issued_at": job["issued_at"],
            "expires_at": job["expires_at"],
            "payload": job["payload"],
        }
        if not verify(SHARED_SECRET, env, job["signature"]):
            continue

        # Relay-local jobs
        if job.get('action') == 'put_state':
            ok, detail = _apply_put_state(job)
            try:
                requests.post(
                    f"{CORE_URL}/v1/relays/{RELAY_ID}/job_results",
                    headers=_auth_header(),
                    json={
                        "job_id": job.get("job_id"),
                        "agent_id": "relay",
                        "ok": bool(ok),
                        "detail": detail,
                        "metadata": {"action": "put_state"},
                        "finished_at": _now_iso(),
                    },
                    timeout=10,
                )
            except Exception:
                pass
            # still record it locally for audit
        db.upsert_job(
            job_id=job["job_id"],
            relay_id=job["relay_id"],
            action=job["action"],
            issued_at=job["issued_at"],
            expires_at=job["expires_at"],
            payload=job["payload"],
            signature=job["signature"],
        )

def _poll_loop():
    while True:
        try:
            _relay_checkin()
        except Exception:
            pass
        time.sleep(POLL_SECONDS)

@app.on_event("startup")
def _startup():
    if POLL_ENABLED:
        t = threading.Thread(target=_poll_loop, daemon=True)
        t.start()

@app.post("/v1/edge/poll", dependencies=[Depends(require_edge_key)])
def poll_core_now():
    _relay_checkin()
    return {"ok": True}

@app.post("/v1/agents/checkin", response_model=list[JobEnvelope], dependencies=[Depends(require_edge_key)])
def agent_checkin(body: AgentCheckin):
    ts = _now_iso()
    db.upsert_agent(
        agent_id=body.agent_id,
        last_seen_at=ts,
        platform=body.platform,
        version=body.version,
        caps=body.caps,
        logging=body.logging,
    )

    _push_dashboard({
        "type": "status_update",
        "relays": [],
        "agents": [{"agent_id": body.agent_id, "relay_id": RELAY_ID, "status": "ok", "last_seen": ts, "hostname": body.platform or "", "ip": ""}],
    })

    rows = db.jobs_for_agent(RELAY_ID, body.agent_id, limit=body.max_jobs)
    out = []
    for r in rows:
        env = {
            "relay_id": r[1],
            "action": r[2],
            "issued_at": r[3],
            "expires_at": r[4],
            "payload": json.loads(r[5]),
        }
        sig = r[6]
        if not verify(SHARED_SECRET, env, sig):
            continue

        out.append(JobEnvelope(
            job_id=r[0],
            relay_id=r[1],
            action=r[2],
            issued_at=datetime.datetime.fromisoformat(r[3]),
            expires_at=datetime.datetime.fromisoformat(r[4]),
            payload=json.loads(r[5]),
            signature=sig,
        ))
    return out

@app.post("/v1/agents/job_results", dependencies=[Depends(require_edge_key)])
def agent_job_results(body: AgentJobResult):
    try:
        requests.post(
            f"{CORE_URL}/v1/relays/{RELAY_ID}/job_results",
            headers=_auth_header(),
            json={
                "job_id": body.job_id,
                "agent_id": body.agent_id,
                "ok": body.ok,
                "detail": body.detail,
                "metadata": body.metadata,
                "finished_at": body.finished_at.isoformat(),
            },
            timeout=10,
        )
    except Exception:
        pass

    _push_dashboard({
        "type": "campaign_event",
        "campaign_id": body.metadata.get("campaign_ref", "") if body.metadata else "",
        "event_type": "job_result",
        "severity": "info" if body.ok else "high",
        "metadata": {"job_id": body.job_id, "agent_id": body.agent_id, "relay_id": RELAY_ID, "ok": body.ok, "detail": body.detail},
    })

    return {"ok": True}


def _spool_append(line: str) -> None:
    try:
        # naive size cap (rotate)
        if os.path.exists(EDGE_EVENTS_SPOOL):
            sz = os.path.getsize(EDGE_EVENTS_SPOOL)
            if sz > EDGE_EVENTS_MAX_SPOOL_MB * 1024 * 1024:
                os.replace(EDGE_EVENTS_SPOOL, EDGE_EVENTS_SPOOL + ".1")
        with open(EDGE_EVENTS_SPOOL, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def _forward_event(ecs: dict) -> bool:
    try:
        import requests
        r = requests.post(EDGE_EVENTS_FORWARD, json=ecs, headers={"Authorization": f"Bearer {EDGE_API_KEY}"}, timeout=3.0)
        return r.status_code < 300
    except Exception:
        return False

@app.post("/v1/events")
def ingest_event(body: dict):
    """Accept ECS-ish JSON from local agents/providers and forward to controller. Also optionally log locally."""
    line = json.dumps(body, separators=(",", ":"))
    ok = _forward_event(body)
    if not ok:
        _spool_append(line)
    return {"ok": True, "forwarded": ok}

@app.post("/v1/agents/logs", dependencies=[Depends(require_edge_key)])
def agent_logs(body: AgentLog):
    global _last_so_send_at, _last_so_send_ok
    line = json.dumps(body.ecs, separators=(",", ":"), ensure_ascii=False)
    _last_so_send_at = _now_iso()
    try:
        syslog.send(line)
        _last_so_send_ok = True
    except Exception:
        _last_so_send_ok = False
    return {"ok": True, "so_forward_ok": bool(_last_so_send_ok)}

def main():
    import uvicorn
    uvicorn.run("relay.app:app", host="0.0.0.0", port=int(os.environ.get("PORT", "9443")), reload=False)

if __name__ == "__main__":
    main()
def _flush_spool_worker():
    import time
    while True:
        try:
            if os.path.exists(EDGE_EVENTS_SPOOL):
                # best-effort: read all lines and try forward; keep failures
                with open(EDGE_EVENTS_SPOOL, "r", encoding="utf-8") as f:
                    lines = [ln.strip() for ln in f.readlines() if ln.strip()]
                if lines:
                    keep = []
                    for ln in lines:
                        try:
                            ecs = json.loads(ln)
                        except Exception:
                            continue
                        if not _forward_event(ecs):
                            keep.append(ln)
                    # rewrite spool with remaining
                    with open(EDGE_EVENTS_SPOOL, "w", encoding="utf-8") as f:
                        for ln in keep:
                            f.write(ln + "\n")
        except Exception:
            pass
        time.sleep(5)

@app.on_event("startup")
def _on_startup_relay():
    import threading
    t = threading.Thread(target=_flush_spool_worker, daemon=True)
    t.start()
