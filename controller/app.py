from __future__ import annotations
import os, json, secrets, base64
import datetime
from datetime import timedelta, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Request, Response
from controller.db import DB
from controller.models import (
    CampaignCreate, CampaignOut, CampaignObjectCreate, CampaignObjectOut,
    DeployRequest, JobEnvelope, TokenCreate, TokenOut, CampaignStatusOut,
    RelayCheckinIn, OpsStatusOut, OpsRelayOut, OpsAgentOut, OpsSummaryOut,
    CampaignOpsOut, CampaignTargetOut,
    new_id, now
)
from controller.signing import sign
from controller.providers.canary import CanaryProvider
from controller.rules import RulesEngine, Guardrails
from controller.telemetry import SyslogForwarder, ecs_doc
from controller import pusher

DB_PATH = os.environ.get("TRACED_CONTROLLER_DB", "./controller.db")
SHARED_SECRET = os.environ.get("TRACED_SHARED_SECRET", "change-me").encode("utf-8")

OPS_API_KEY = os.environ.get("OPS_API_KEY", "")
OPS_API_KEY_PREV = os.environ.get("OPS_API_KEY_PREV", "")
EDGE_API_KEY = os.environ.get("EDGE_API_KEY", "")
EDGE_API_KEY_PREV = os.environ.get("EDGE_API_KEY_PREV", "")

SO_HOST = os.environ.get("TRACED_SO_HOST", "").strip()
SO_PORT = int(os.environ.get("TRACED_SO_PORT", "514"))
SO_PROTO = os.environ.get("TRACED_SO_PROTO", "udp")

RELAY_STALE_SEC = int(os.environ.get("OPS_RELAY_STALE_SEC", "90"))
AGENT_STALE_SEC = int(os.environ.get("OPS_AGENT_STALE_SEC", "120"))
EVENT_RETENTION_DAYS = int(os.environ.get("EVENT_RETENTION_DAYS", "14"))
EVENT_RETENTION_SWEEP_SEC = int(os.environ.get("EVENT_RETENTION_SWEEP_SEC", "3600"))

db = DB(DB_PATH)
app = FastAPI(title="TRACED Controller", version="0.6.0")
syslog = SyslogForwarder(SO_HOST, SO_PORT, SO_PROTO) if SO_HOST else None

def emit_alert(doc: dict) -> None:
    # Ensure ECS-ish doc has timestamp and is shipped as JSON line to Security Onion if configured.
    try:
        line = json.dumps(doc, separators=(",", ":"))
    except Exception:
        return
    if syslog:
        try:
            syslog.send(line)
        except Exception:
            pass

guard = Guardrails(
    max_actions_per_source_per_10m=int(os.environ.get("GUARD_MAX_ACTIONS_PER_SOURCE_10M", "10")),
    max_tokens_per_campaign_per_day=int(os.environ.get("GUARD_MAX_TOKENS_PER_CAMPAIGN_DAY", "20")),
    max_state_updates_per_provider_per_10m=int(os.environ.get("GUARD_MAX_STATE_UPDATES_PER_PROVIDER_10M", "5")),
    max_deploys_per_campaign_per_hour=int(os.environ.get("GUARD_MAX_DEPLOYS_PER_CAMPAIGN_HOUR", "10")),
    dedupe_window_sec=int(os.environ.get("GUARD_DEDUPE_WINDOW_SEC", "600")),
    breaker_events_per_minute=int(os.environ.get("GUARD_BREAKER_EVENTS_PER_MIN", "500")),
    breaker_hold_sec=int(os.environ.get("GUARD_BREAKER_HOLD_SEC", "1800")),
)

rules_engine = RulesEngine(db=db, guardrails=guard, emit_alert=emit_alert)

_canary: CanaryProvider | None = None
def canary() -> CanaryProvider:
    global _canary
    if _canary is None:
        _canary = CanaryProvider()
    return _canary

def _parse_iso(s: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(s)


def _utcz(dt) -> str:
    """Normalize UTC datetime to Z-suffix ISO for consistent HMAC signing."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(timezone.utc)

def utcnow_plus_minutes(minutes: int) -> str:
    """ISO8601 Z-suffixed UTC timestamp `minutes` in the future (enroll token expiry)."""
    return _utcz(_now_utc() + timedelta(minutes=minutes))

def _age_sec(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = _parse_iso(iso)
        return int((_now_utc() - dt).total_seconds())
    except Exception:
        return None

def _bearer_token(authorization: str | None) -> str:
    if not authorization:
        return ""
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()

def _require_any_key(authorization: str | None, keys: list[str]) -> None:
    token = _bearer_token(authorization)
    allowed = {k for k in keys if k}
    if not allowed:
        raise HTTPException(503, "auth_not_configured")
    if token not in allowed:
        raise HTTPException(401, "unauthorized")

def require_ops_key(authorization: str | None = Header(default=None)) -> None:
    _require_any_key(authorization, [OPS_API_KEY, OPS_API_KEY_PREV])

def require_edge_key(authorization: str | None = Header(default=None)) -> None:
    _require_any_key(authorization, [EDGE_API_KEY, EDGE_API_KEY_PREV])

def _campaign_status(starts_at: str | None, ends_at: str | None, current_status: str) -> str:
    if current_status == "stopped":
        return "stopped"
    t = now()
    s = _parse_iso(starts_at) if starts_at else None
    e = _parse_iso(ends_at) if ends_at else None
    if s and t < s:
        return "scheduled"
    if e and t > e:
        return "expired"
    if not s and not e:
        return "active" if current_status == "active" else "draft"
    return "active"

def _sync_campaign_status(campaign_id: str) -> str:
    camp = db.get_campaign(campaign_id)
    if not camp:
        return "missing"
    status = _campaign_status(camp["starts_at"], camp["ends_at"], camp["status"])
    if status != camp["status"]:
        db.update_campaign_status(campaign_id, status)
    return status

def _new_correlation_id() -> str:
    return secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:14].upper()

@app.get("/v1/status")
def status():
    return {"ok": True, "service": "controller", "time": now().isoformat()}

# ---------- Campaigns ----------

@app.post("/v1/campaigns", response_model=CampaignOut, dependencies=[Depends(require_ops_key)])
def create_campaign(body: CampaignCreate):
    cid = new_id()
    ts = now()
    starts = body.starts_at.isoformat() if body.starts_at else None
    ends = body.ends_at.isoformat() if body.ends_at else None

    db.create_campaign(
        id=cid,
        name=body.name,
        objective=body.objective,
        tags=body.tags,
        starts_at=starts,
        ends_at=ends,
        created_at=ts.isoformat(),
    )
    status = _sync_campaign_status(cid)
    return CampaignOut(
        id=cid,
        name=body.name,
        objective=body.objective,
        tags=body.tags,
        starts_at=body.starts_at,
        ends_at=body.ends_at,
        status=status,
        created_at=ts,
    )

@app.get("/v1/campaigns", response_model=list[CampaignOut], dependencies=[Depends(require_ops_key)])
def list_campaigns():
    out: list[CampaignOut] = []
    for r in db.list_campaigns():
        cid = r["id"]
        status = _sync_campaign_status(cid)
        out.append(CampaignOut(
            id=r["id"],
            name=r["name"],
            objective=r["objective"],
            tags=json.loads(r["tags"]),
            starts_at=(_parse_iso(r["starts_at"]) if r["starts_at"] else None),
            ends_at=(_parse_iso(r["ends_at"]) if r["ends_at"] else None),
            phase=r["phase"],
            status=status,
            created_at=_parse_iso(r["created_at"]),
        ))
    return out

@app.get("/v1/campaigns/{campaign_id}/status", response_model=CampaignStatusOut, dependencies=[Depends(require_ops_key)])
def campaign_status(campaign_id: str):
    camp = db.get_campaign(campaign_id)
    if not camp:
        raise HTTPException(404, "campaign not found")
    status = _sync_campaign_status(campaign_id)
    s = db.campaign_status_summary(campaign_id)
    return CampaignStatusOut(
        campaign_id=campaign_id,
        status=status,
        starts_at=camp["starts_at"],
        ends_at=camp["ends_at"],
        objects=s["objects"],
        tokens=s["tokens"],
        token_hits=s["token_hits"],
        last_hit_at=s["last_hit_at"],
    )

@app.post("/v1/campaigns/{campaign_id}/objects", response_model=CampaignObjectOut, dependencies=[Depends(require_ops_key)])
def add_object(campaign_id: str, body: CampaignObjectCreate):
    if not db.get_campaign(campaign_id):
        raise HTTPException(404, "campaign not found")
    oid = new_id()
    ts = now()
    db.add_object(
        id=oid,
        campaign_id=campaign_id,
        object_type=body.object_type,
        name=body.name,
        cfg=body.cfg,
        tags=body.tags,
        created_at=ts.isoformat(),
    )
    return CampaignObjectOut(
        id=oid,
        campaign_id=campaign_id,
        object_type=body.object_type,
        name=body.name,
        cfg=body.cfg,
        tags=body.tags,
        created_at=ts,
    )

# ---------- Tokens (provider-backed) ----------

@app.post("/v1/campaigns/{campaign_id}/tokens", response_model=TokenOut, dependencies=[Depends(require_ops_key)])
def add_token(campaign_id: str, body: TokenCreate):
    if not db.get_campaign(campaign_id):
        raise HTTPException(404, "campaign not found")

    corr = _new_correlation_id()
    memo = f"campaign={campaign_id} corr={corr} agent={body.agent_id}"

    tok = canary().create(kind=body.kind, memo=memo)
    provider_token_id = tok["canarytoken"]
    provider_url = tok.get("url")
    download_name = None

    if body.kind == "pdf-acrobat-reader":
        fname, blob = canary().download(provider_token_id=provider_token_id)
        download_name = fname
        b64 = base64.b64encode(blob).decode("ascii")

        obj_id = new_id()
        obj_name = f"doc-{corr.lower()}"
        cfg = {
            "path": body.placement.get("path") or f"~/Documents/{fname}",
            "content_b64": b64,
            "mode": "0644",
        }
        tags = body.tags + ["provider:canary", "kind:pdf"]
        db.add_object(
            id=obj_id,
            campaign_id=campaign_id,
            object_type="file_artifact",
            name=obj_name,
            cfg=cfg,
            tags=tags,
            created_at=now().isoformat(),
        )
        db.upsert_correlation(
            correlation_id=corr,
            campaign_id=campaign_id,
            object_id=obj_id,
            object_name=obj_name,
            agent_id=body.agent_id,
            created_at=now().isoformat(),
        )

    db.add_token(
        id=new_id(),
        campaign_id=campaign_id,
        agent_id=body.agent_id,
        relay_id=body.relay_id,
        correlation_id=corr,
        provider="canary",
        kind=body.kind,
        provider_token_id=provider_token_id,
        provider_url=provider_url,
        download_name=download_name,
        created_at=now().isoformat(),
        cfg_json=json.dumps({"placement": body.placement, "tags": body.tags}),
    )

    return TokenOut(
        correlation_id=corr,
        provider="canary",
        kind=body.kind,
        provider_token_id=provider_token_id,
        provider_url=provider_url,
        download_name=download_name,
        agent_id=body.agent_id,
        relay_id=body.relay_id,
        hit_count=0,
        last_hit_at=None,
        created_at=now().isoformat(),
    )

@app.get("/v1/campaigns/{campaign_id}/tokens", response_model=list[TokenOut], dependencies=[Depends(require_ops_key)])
def list_tokens(campaign_id: str):
    rows = db.list_tokens(campaign_id)
    out: list[TokenOut] = []
    for r in rows:
        out.append(TokenOut(
            correlation_id=r["correlation_id"],
            provider=r["provider"],
            kind=r["kind"],
            provider_token_id=r["provider_token_id"],
            provider_url=r["provider_url"],
            download_name=r["download_name"],
            agent_id=r["agent_id"],
            relay_id=r["relay_id"],
            hit_count=int(r["hit_count"]),
            last_hit_at=r["last_hit_at"],
            created_at=r["created_at"],
        ))
    return out

# ---------- Deploy / teardown jobs ----------

@app.post("/v1/campaigns/{campaign_id}/deploy", response_model=JobEnvelope, dependencies=[Depends(require_ops_key)])
def deploy_campaign(campaign_id: str, body: DeployRequest):
    camp = db.get_campaign(campaign_id)
    if not camp:
        raise HTTPException(404, "campaign not found")

    status = _sync_campaign_status(campaign_id)
    if status in ("scheduled", "expired", "stopped"):
        raise HTTPException(409, f"campaign not deployable (status={status})")

    objs = db.list_objects(campaign_id)
    if not body.target_agent_ids:
        raise HTTPException(400, "target_agent_ids required")

    issued = now()
    expires = issued + timedelta(minutes=30)

    workloads = []
    for o in objs:
        object_id = o["id"]
        object_type = o["object_type"]
        object_name = o["name"]
        cfg = json.loads(o["cfg"])

        for agent_id in body.target_agent_ids:
            correlation_id = _new_correlation_id()
            db.upsert_correlation(
                correlation_id=correlation_id,
                campaign_id=campaign_id,
                object_id=object_id,
                object_name=object_name,
                agent_id=agent_id,
                created_at=_utcz(issued),
            )
            workloads.append({
                "agent_id": agent_id,
                "workload_type": object_type,
                "workload_id": correlation_id,
                "cfg": cfg,
            })

    payload = {"targets": body.target_agent_ids, "campaign_ref": campaign_id, "workloads": workloads}
    env = {"relay_id": body.relay_id, "action": "apply", "issued_at": _utcz(issued), "expires_at": _utcz(expires), "payload": payload}
    sig = sign(SHARED_SECRET, env)
    job_id = new_id()

    db.add_job(job_id=job_id, relay_id=body.relay_id, action="apply", issued_at=_utcz(issued),
               expires_at=_utcz(expires), payload=payload, signature=sig)

    db.upsert_campaign_targets(
        campaign_id=campaign_id,
        relay_id=body.relay_id,
        agent_ids=body.target_agent_ids,
        targeted_at=_utcz(issued),
        deploy_job_id=job_id,
        teardown_job_id=None,
        status="pending",
    )

    db.update_campaign_status(campaign_id, "active")
    return JobEnvelope(job_id=job_id, relay_id=body.relay_id, action="apply", issued_at=issued, expires_at=expires, payload=payload, signature=sig)

@app.post("/v1/campaigns/{campaign_id}/teardown", response_model=JobEnvelope, dependencies=[Depends(require_ops_key)])
def teardown_campaign(campaign_id: str, body: DeployRequest):
    if not db.get_campaign(campaign_id):
        raise HTTPException(404, "campaign not found")
    if not body.target_agent_ids:
        raise HTTPException(400, "target_agent_ids required")

    issued = now()
    expires = issued + timedelta(minutes=30)
    payload = {"targets": body.target_agent_ids, "campaign_ref": campaign_id, "remove_all_for_campaign": True}
    env = {"relay_id": body.relay_id, "action": "remove", "issued_at": _utcz(issued), "expires_at": _utcz(expires), "payload": payload}
    sig = sign(SHARED_SECRET, env)
    job_id = new_id()

    db.add_job(job_id=job_id, relay_id=body.relay_id, action="remove", issued_at=_utcz(issued),
               expires_at=_utcz(expires), payload=payload, signature=sig)

    db.upsert_campaign_targets(
        campaign_id=campaign_id,
        relay_id=body.relay_id,
        agent_ids=body.target_agent_ids,
        targeted_at=_utcz(issued),
        deploy_job_id=None,
        teardown_job_id=job_id,
        status="pending",
    )

    db.update_campaign_status(campaign_id, "stopped")
    return JobEnvelope(job_id=job_id, relay_id=body.relay_id, action="remove", issued_at=issued, expires_at=expires, payload=payload, signature=sig)

# ---------- Relay endpoints (polling + heartbeat capture) ----------

@app.post("/v1/relays/{relay_id}/checkin", response_model=list[JobEnvelope], dependencies=[Depends(require_edge_key)])
def relay_checkin(relay_id: str, body: RelayCheckinIn | None = None):
    ts = now().isoformat()
    meta = body.meta if body else {}
    ver = body.version if body else None
    agents_seen = int(body.agents_seen or 0) if body else 0
    logging = body.logging if body else {}
    db.upsert_relay(relay_id=relay_id, last_seen_at=ts, version=ver, meta=meta, agents_seen=agents_seen, logging=logging)

    pusher.push_status_update(
        relays=[{"relay_id": relay_id, "status": "ok", "last_seen": ts, "agent_count": agents_seen}],
        agents=[],
    )

    rows = db.list_jobs_for_relay(relay_id)
    out: list[JobEnvelope] = []
    for r in rows:
        out.append(JobEnvelope(
            job_id=r["job_id"],
            relay_id=r["relay_id"],
            action=r["action"],
            issued_at=_parse_iso(r["issued_at"]),
            expires_at=_parse_iso(r["expires_at"]),
            payload=json.loads(r["payload"]),
            signature=r["signature"],
        ))
    return out

@app.post("/v1/relays/{relay_id}/job_results", dependencies=[Depends(require_edge_key)])
def relay_job_results(relay_id: str, body: dict):
    campaign_id = None
    try:
        job_id = body.get("job_id", "")
        row = db.conn.execute("SELECT payload FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row:
            payload = json.loads(row["payload"])
            campaign_id = payload.get("campaign_ref")
    except Exception:
        campaign_id = None

    finished_at = body.get("finished_at") or now().isoformat()
    db.add_job_result(
        id=new_id(),
        job_id=body.get("job_id",""),
        relay_id=relay_id,
        agent_id=body.get("agent_id",""),
        ok=bool(body.get("ok", False)),
        detail=str(body.get("detail","")),
        metadata=body.get("metadata") or {},
        finished_at=finished_at,
    )

    if campaign_id and body.get("agent_id"):
        status = "applied" if bool(body.get("ok", False)) else "error"
        db.mark_target_applied(
            campaign_id=campaign_id,
            agent_id=body["agent_id"],
            applied_at=finished_at,
            status=status,
            detail=str(body.get("detail","")),
        )

    # Push campaign_event for job result
    if campaign_id:
        status_str = "applied" if bool(body.get("ok", False)) else "error"
        pusher.push_campaign_event(
            campaign_id=campaign_id,
            event_type="job_result",
            severity="info" if status_str == "applied" else "high",
            metadata={"job_id": body.get("job_id",""), "agent_id": body.get("agent_id",""), "relay_id": relay_id, "status": status_str, "detail": str(body.get("detail",""))},
        )

    return {"ok": True}

# ---------- Ops: status endpoints ----------


@app.post("/v1/ops/enroll/relay", dependencies=[Depends(require_ops_key)])
def ops_create_relay_enroll(body: dict, request: Request):
    # Minimal defaults
    expires_minutes = int(body.get("expires_minutes", 60))
    poll_seconds = int(body.get("poll_seconds", 15))
    so_host = body.get("so_host", "")
    so_port = int(body.get("so_port", 514))
    so_proto = body.get("so_proto", "udp")
    # Controller URL for the installer script to call back to
    controller_url = body.get("controller_url")
    if not controller_url:
        # best-effort guess from incoming request
        controller_url = str(request.base_url).rstrip("/")
    expires_at = utcnow_plus_minutes(expires_minutes)

    cfg = {
        "controller_url": controller_url,
        "core_url": body.get("core_url") or controller_url,  # relay CORE_URL points to controller
        "traced_shared_secret": os.environ.get("TRACED_SHARED_SECRET", ""),
        "edge_api_key": os.environ.get("EDGE_API_KEY", ""),
        "edge_poll_seconds": poll_seconds,
        "edge_so_host": so_host,
        "edge_so_port": so_port,
        "edge_so_proto": so_proto,
    }
    if not cfg["traced_shared_secret"] or not cfg["edge_api_key"]:
        raise HTTPException(500, "controller missing TRACED_SHARED_SECRET/EDGE_API_KEY")

    token = db.create_enroll_token(kind="relay", expires_at=expires_at, config=cfg)
    cmd = f'curl -fsSL "{controller_url}/v1/enroll/relay.sh?token={token}" | sudo bash'
    return {"ok": True, "token": token, "expires_at": expires_at, "command": cmd}

@app.get("/v1/enroll/relay-config")
def enroll_relay_config(token: str):
    ok, msg, cfg = db.is_enroll_valid(token, "relay")
    if not ok:
        raise HTTPException(401, msg)
    # Return only what installer needs
    return {
        "core_url": cfg["core_url"],
        "controller_url": cfg["controller_url"],
        "traced_shared_secret": cfg["traced_shared_secret"],
        "edge_api_key": cfg["edge_api_key"],
        "edge_poll_seconds": cfg["edge_poll_seconds"],
        "edge_so_host": cfg.get("edge_so_host",""),
        "edge_so_port": cfg.get("edge_so_port",514),
        "edge_so_proto": cfg.get("edge_so_proto","udp"),
        "bundle_version": APP_VERSION,
    }

@app.get("/v1/enroll/relay-bundle.manifest.json")
def enroll_relay_bundle_manifest(token: str):
    ok, msg, _cfg = db.is_enroll_valid(token, "relay")
    if not ok:
        raise HTTPException(401, msg)
    data, mani = build_relay_bundle(Path(__file__).resolve().parents[1], APP_VERSION)
    return {"name": mani.name, "version": mani.version, "sha256": mani.sha256, "size_bytes": mani.size_bytes}

@app.get("/v1/enroll/relay-bundle.tgz")
def enroll_relay_bundle(token: str):
    ok, msg, _cfg = db.is_enroll_valid(token, "relay")
    if not ok:
        raise HTTPException(401, msg)
    data, mani = build_relay_bundle(Path(__file__).resolve().parents[1], APP_VERSION)
    return Response(content=data, media_type="application/gzip", headers={
        "Content-Disposition": f'attachment; filename="relay-bundle-{mani.version}.tgz"',
        "X-Bundle-SHA256": mani.sha256,
    })

@app.get("/v1/enroll/relay.sh")
def enroll_relay_script(token: str):
    ok, msg, cfg = db.is_enroll_valid(token, "relay")
    if not ok:
        raise HTTPException(401, msg)
    controller_url = cfg["controller_url"].rstrip("/")
    # Single-file installer: fetches config+manifest+bundle from controller, verifies sha256, installs systemd, smoke-tests.
    script = f'''#!/usr/bin/env bash
set -euo pipefail

CONTROLLER="{controller_url}"
TOKEN="{token}"

need_cmd() {{ command -v "$1" >/dev/null 2>&1; }}

echo "[*] Installing prerequisites"
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release rsync jq python3 tar

if ! need_cmd docker; then
  echo "[*] Installing Docker Engine + Compose plugin"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable docker >/dev/null
systemctl start docker

echo "[*] Fetching enroll config"
CFG="$(curl -fsSL "$CONTROLLER/v1/enroll/relay-config?token=$TOKEN")"
CORE_URL="$(echo "$CFG" | jq -r .core_url)"
SHARED_SECRET="$(echo "$CFG" | jq -r .traced_shared_secret)"
EDGE_API_KEY="$(echo "$CFG" | jq -r .edge_api_key)"
POLL_SECONDS="$(echo "$CFG" | jq -r .edge_poll_seconds)"
SO_HOST="$(echo "$CFG" | jq -r .edge_so_host)"
SO_PORT="$(echo "$CFG" | jq -r .edge_so_port)"
SO_PROTO="$(echo "$CFG" | jq -r .edge_so_proto)"

if [[ -z "$SHARED_SECRET" || -z "$EDGE_API_KEY" ]]; then
  echo "ERROR: controller returned empty secrets"
  exit 2
fi

echo "[*] Creating/reading opaque relay id"
DIR="/etc/traced"
FILE="$DIR/relay_id"
mkdir -p "$DIR"
chmod 700 "$DIR"
if [[ -f "$FILE" ]]; then
  RELAY_ID="$(cat "$FILE")"
else
  RELAY_ID="rly_$(python3 - <<'PY'
import secrets
alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
print("".join(secrets.choice(alphabet) for _ in range(12)))
PY
)"
  echo "$RELAY_ID" > "$FILE"
  chmod 600 "$FILE"
fi
echo "[*] Relay ID: $RELAY_ID"

echo "[*] Collecting mapping metadata"
HOSTNAME="$(hostname)"
MODEL="$(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null || true)"
SERIAL="$(cat /sys/devices/virtual/dmi/id/product_serial 2>/dev/null || true)"
ARCH="$(uname -m)"
cat > /etc/traced/mapping.json <<EOF
{{"relay_id":"$RELAY_ID","hostname":"$HOSTNAME","model":"${{MODEL//"/\"}}","serial":"${{SERIAL//"/\"}}","arch":"$ARCH"}}
EOF
chmod 600 /etc/traced/mapping.json

echo "[*] Fetching bundle manifest"
MANI="$(curl -fsSL "$CONTROLLER/v1/enroll/relay-bundle.manifest.json?token=$TOKEN")"
BUNDLE_SHA="$(echo "$MANI" | jq -r .sha256)"
BUNDLE_VER="$(echo "$MANI" | jq -r .version)"

echo "[*] Downloading relay bundle (version $BUNDLE_VER)"
TMPDIR="$(mktemp -d)"
BUNDLE="$TMPDIR/relay-bundle.tgz"
curl -fsSL "$CONTROLLER/v1/enroll/relay-bundle.tgz?token=$TOKEN" -o "$BUNDLE"

echo "[*] Verifying sha256"
DOWN_SHA="$(sha256sum "$BUNDLE" | awk '{{print $1}}')"
if [[ "$DOWN_SHA" != "$BUNDLE_SHA" ]]; then
  echo "ERROR: bundle sha mismatch"
  echo " expected=$BUNDLE_SHA"
  echo " got=$DOWN_SHA"
  exit 3
fi

INSTALL_DIR="/opt/traced-mvp"
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR"/*
tar -xzf "$BUNDLE" -C "$INSTALL_DIR"

echo "[*] Writing env"
cat > "$INSTALL_DIR/.env" <<EOF
TRACED_SHARED_SECRET=$SHARED_SECRET
EDGE_API_KEY=$EDGE_API_KEY
EDGE_RELAY_ID=$RELAY_ID
EDGE_POLL_SECONDS=$POLL_SECONDS
EDGE_SO_HOST=$SO_HOST
EDGE_SO_PORT=$SO_PORT
EDGE_SO_PROTO=$SO_PROTO
EDGE_META_HOSTNAME=$HOSTNAME
EDGE_META_MODEL=$MODEL
EDGE_META_SERIAL=$SERIAL
EDGE_META_ARCH=$ARCH
CORE_URL=$CORE_URL
EOF

echo "[*] Installing systemd unit"
tmpl="$INSTALL_DIR/deploy/traced-relay.service.tmpl"
unit="/etc/systemd/system/traced-relay.service"
sed "s|{{CORE_URL}}|$CORE_URL|g" "$tmpl" > "$unit"

systemctl daemon-reload
systemctl enable traced-relay.service >/dev/null
systemctl restart traced-relay.service

echo "[*] Smoke test: local relay poll"
sleep 2
curl -fsSL -X POST http://127.0.0.1:9443/v1/edge/poll -H "Authorization: Bearer $EDGE_API_KEY" >/dev/null
echo "[*] Relay is up."

echo "[*] Done."
'''
    return Response(content=script, media_type="text/x-shellscript")


@app.get("/v1/ops/events", dependencies=[Depends(require_ops_key)])
def ops_list_events(kind: str | None = None, campaign_id: str | None = None, since: str | None = None, limit: int = 200):
    rows = db.list_events(kind=kind, campaign_id=campaign_id, since=since, limit=limit)
    return {"events": [json.loads(r["body_json"]) for r in rows]}

@app.get("/v1/ops/alerts", dependencies=[Depends(require_ops_key)])
def ops_list_alerts(campaign_id: str | None = None, since: str | None = None, limit: int = 200):
    rows = db.list_events(kind="alert", campaign_id=campaign_id, since=since, limit=limit)
    return {"alerts": [json.loads(r["body_json"]) for r in rows]}

@app.post("/v1/ops/campaigns/{campaign_id}/purge", dependencies=[Depends(require_ops_key)])
def ops_purge_campaign(campaign_id: str, body: dict | None = None):
    purge_events = True
    if body and "purge_events" in body:
        purge_events = bool(body["purge_events"])
    return db.purge_campaign(campaign_id, purge_events=purge_events)

@app.get("/v1/ops/status", response_model=OpsStatusOut, dependencies=[Depends(require_ops_key)])
def ops_status():
    t = _now_utc().isoformat()
    relays = []
    agents = []
    relays_ok = relays_stale = agents_ok = agents_stale = 0

    for r in db.list_relays():
        age = _age_sec(r["last_seen_at"])
        st = "ok" if (age is not None and age <= RELAY_STALE_SEC) else "stale"
        if st == "ok": relays_ok += 1
        else: relays_stale += 1
        relays.append(OpsRelayOut(
            relay_id=r["relay_id"],
            last_seen_at=r["last_seen_at"],
            age_sec=age,
            status=st,
            version=r["version"],
            agents_seen=int(r["agents_seen"] or 0),
            logging=json.loads(r["logging_json"] or "{}"),
        ))

    for a in db.list_agents():
        age = _age_sec(a["last_seen_at"])
        st = "ok" if (age is not None and age <= AGENT_STALE_SEC) else "stale"
        if st == "ok": agents_ok += 1
        else: agents_stale += 1
        agents.append(OpsAgentOut(
            agent_id=a["agent_id"],
            relay_id=a["relay_id"],
            last_seen_at=a["last_seen_at"],
            age_sec=age,
            status=st,
            platform=a["platform"],
            version=a["version"],
            caps=json.loads(a["caps_json"] or "{}"),
            logging=json.loads(a["logging_json"] or "{}"),
        ))

    return OpsStatusOut(
        time=t,
        relays=relays,
        agents=agents,
        summary=OpsSummaryOut(relays_ok=relays_ok, relays_stale=relays_stale, agents_ok=agents_ok, agents_stale=agents_stale),
    )


@app.put("/v1/ops/relays/{relay_id}/label", dependencies=[Depends(require_ops_key)])
def set_relay_label(relay_id: str, body: dict):
    if not db.get_relay(relay_id):
        raise HTTPException(404, "relay not found")
    label = body.get("label")
    if label is not None:
        label = str(label).strip()
        if len(label) > 64:
            raise HTTPException(400, "label too long")
        if label == "":
            label = None
    db.set_relay_label(relay_id, label)
    return {"ok": True, "relay_id": relay_id, "label": label}

@app.get("/v1/ops/relays/{relay_id}", dependencies=[Depends(require_ops_key)])
def ops_relay(relay_id: str):
    r = db.get_relay(relay_id)
    if not r:
        raise HTTPException(404, "relay not found")
    agents = []
    for a in db.list_agents_for_relay(relay_id):
        agents.append({
            "agent_id": a["agent_id"],
            "last_seen_at": a["last_seen_at"],
            "age_sec": _age_sec(a["last_seen_at"]),
            "platform": a["platform"],
            "version": a["version"],
            "caps": json.loads(a["caps_json"] or "{}"),
            "logging": json.loads(a["logging_json"] or "{}"),
        })
    return {
        "relay": {
            "relay_id": r["relay_id"],
            "label": r["label"],
            "meta": json.loads(r["meta_json"] or "{}"),
            "last_seen_at": r["last_seen_at"],
            "age_sec": _age_sec(r["last_seen_at"]),
            "version": r["version"],
            "agents_seen": int(r["agents_seen"] or 0),
            "logging": json.loads(r["logging_json"] or "{}"),
        },
        "agents": agents,
    }

@app.get("/v1/ops/agents/{agent_id}", dependencies=[Depends(require_ops_key)])
def ops_agent(agent_id: str):
    a = db.get_agent(agent_id)
    if not a:
        raise HTTPException(404, "agent not found")
    return {
        "agent_id": a["agent_id"],
        "relay_id": a["relay_id"],
        "last_seen_at": a["last_seen_at"],
        "age_sec": _age_sec(a["last_seen_at"]),
        "platform": a["platform"],
        "version": a["version"],
        "caps": json.loads(a["caps_json"] or "{}"),
        "logging": json.loads(a["logging_json"] or "{}"),
    }

@app.get("/v1/campaigns/{campaign_id}/ops", response_model=CampaignOpsOut, dependencies=[Depends(require_ops_key)])
def campaign_ops(campaign_id: str):
    camp = db.get_campaign(campaign_id)
    if not camp:
        raise HTTPException(404, "campaign not found")
    status = _sync_campaign_status(campaign_id)

    targets = []
    applied = pending = errors = stale_agents = 0
    total_hits = 0
    last_hit_at = None

    for trow in db.list_campaign_targets(campaign_id):
        agent = db.get_agent(trow["agent_id"])
        agent_last_seen = agent["last_seen_at"] if agent else None
        agent_age = _age_sec(agent_last_seen)
        if agent_age is None or agent_age > AGENT_STALE_SEC:
            stale_agents += 1

        state = trow["last_status"]
        if state == "applied": applied += 1
        elif state == "error": errors += 1
        else: pending += 1

        lr = db.latest_job_result_for_agent_campaign(campaign_id, trow["agent_id"])
        hits = db.token_hit_summary_for_campaign_agent(campaign_id, trow["agent_id"])
        total_hits += int(hits["count"] or 0)
        if hits["last_hit_at"] and (last_hit_at is None or hits["last_hit_at"] > last_hit_at):
            last_hit_at = hits["last_hit_at"]

        logging = json.loads(agent["logging_json"] or "{}") if agent else {}

        targets.append(CampaignTargetOut(
            relay_id=trow["relay_id"],
            agent_id=trow["agent_id"],
            targeted_at=trow["targeted_at"],
            deploy_state=state,
            agent_last_seen_at=agent_last_seen,
            agent_age_sec=agent_age,
            last_applied_at=trow["last_applied_at"],
            last_job_result=lr,
            token_hits=hits,
            logging=logging,
        ))

    return CampaignOpsOut(
        campaign_id=campaign_id,
        status=status,
        targets=targets,
        summary={
            "targets": len(targets),
            "applied": applied,
            "pending": pending,
            "errors": errors,
            "stale_agents": stale_agents,
            "token_hits": total_hits,
            "last_hit_at": last_hit_at,
        },
    )

# ---------- Integrations: Canary webhook ingestion ----------

def _extract_canarytoken_id(payload: dict) -> str | None:
    for k in ("canarytoken", "token", "token_id"):
        if isinstance(payload.get(k), str):
            return payload[k]
    for nk in ("canarytoken_info", "canarytoken_data", "data", "alert"):
        v = payload.get(nk)
        if isinstance(v, dict):
            for k in ("canarytoken", "token", "token_id"):
                if isinstance(v.get(k), str):
                    return v[k]
    return None

def _auto_expand_after_hit(token_row: dict) -> None:
    campaign_id = token_row["campaign_id"]
    agent_id = token_row["agent_id"]
    relay_id = token_row["relay_id"]

    cfg = {
        "path": f"~/Documents/followup-notes-{token_row['correlation_id'].lower()}.txt",
        "content": "Budget notes: vendor shortlist, renewal timelines, escalation contacts.",
        "mode": "0644",
    }
    tags = ["engage:phase:operate", "adaptation:auto", "lure:document"]

    obj_id = new_id()
    obj_name = f"followup-notes-{token_row['correlation_id'].lower()}"
    db.add_object(id=obj_id, campaign_id=campaign_id, object_type="file_artifact", name=obj_name, cfg=cfg, tags=tags, created_at=now().isoformat())

    corr2 = _new_correlation_id()
    db.upsert_correlation(correlation_id=corr2, campaign_id=campaign_id, object_id=obj_id, object_name=obj_name, agent_id=agent_id, created_at=now().isoformat())

    issued = now()
    expires = issued + timedelta(minutes=30)
    payload = {"targets": [agent_id], "campaign_ref": campaign_id, "workloads": [{"agent_id": agent_id, "workload_type": "file_artifact", "workload_id": corr2, "cfg": cfg}]}
    env = {"relay_id": relay_id, "action": "apply", "issued_at": _utcz(issued), "expires_at": _utcz(expires), "payload": payload}
    sig = sign(SHARED_SECRET, env)
    db.add_job(job_id=new_id(), relay_id=relay_id, action="apply", issued_at=_utcz(issued), expires_at=_utcz(expires), payload=payload, signature=sig)


# --- events ingest + rules ---
@app.post("/v1/events/ingest", dependencies=[Depends(require_edge_key)])
def ingest_event(body: dict):
    """
    Ingest ECS-ish JSON events from relays/agents (direct or via relay forwarder).
    Stores events locally, evaluates rules, emits alerts (and optionally forwards to syslog).
    """
    kind = "event"
    if (body.get("event") or {}).get("kind") == "alert":
        kind = "alert"
    db.insert_event(kind, body)

    pusher.push_campaign_event(
        campaign_id=body.get("campaign_id") or (body.get("event") or {}).get("campaign_id") or "",
        event_type=(body.get("event") or {}).get("action") or kind,
        severity="high" if kind == "alert" else "info",
        metadata=body,
    )
    # Optional forward to external SIEM (e.g., Security Onion)
    try:
        if forwarder.enabled_for(kind):
            forwarder.send_syslog_json(body)
    except Exception:
        pass
    # Evaluate rules (rules engine may emit additional alert events)
    try:
        from controller import rules as rules_engine
        rules_engine.evaluate_and_dispatch(db=db, event=body)
    except Exception:
        pass
    return {"ok": True}

@app.get("/v1/ops/rules")
def list_rules(state: str | None = None, _: None = Depends(require_ops_key)):
    rows = db.list_rules(state=state)
    out = []
    for r in rows:
        out.append({
            "rule_id": r["rule_id"],
            "name": r["name"],
            "state": r["state"],
            "enabled": bool(int(r["enabled"])),
            "scope": r["scope"],
            "definition": json.loads(r["definition_json"]),
            "updated_at": r["updated_at"],
        })
    return {"ok": True, "rules": out}


@app.post("/v1/ops/rules")
def create_rule(body: dict, _: None = Depends(require_ops_key)):
    now_iso = now()
    rule_id = body.get("id") or new_id("rule")
    name = body.get("name") or rule_id
    scope = body.get("scope") or "global"
    definition = body
    definition["id"] = rule_id
    definition.setdefault("enabled", False)
    db.upsert_rule(rule_id=rule_id, name=name, state="draft", enabled=False, scope=scope, definition=definition, now=now_iso)
    return {"ok": True, "rule_id": rule_id, "state": "draft"}


@app.put("/v1/ops/rules/{rule_id}")
def update_rule(rule_id: str, body: dict, _: None = Depends(require_ops_key)):
    row = db.get_rule(rule_id)
    if not row:
        raise HTTPException(404, "rule_not_found")
    if row["state"] != "draft":
        raise HTTPException(409, "rule_not_draft")
    now_iso = now()
    name = body.get("name") or row["name"]
    scope = body.get("scope") or row["scope"]
    body["id"] = rule_id
    db.upsert_rule(rule_id=rule_id, name=name, state="draft", enabled=False, scope=scope, definition=body, now=now_iso)
    return {"ok": True}


@app.post("/v1/ops/rules/{rule_id}/approve")
def approve_rule(rule_id: str, _: None = Depends(require_ops_key)):
    row = db.get_rule(rule_id)
    if not row:
        raise HTTPException(404, "rule_not_found")
    db.set_rule_state(rule_id, state="active", enabled=True, now=now())
    return {"ok": True, "state": "active"}


@app.post("/v1/ops/rules/{rule_id}/disable")
def disable_rule(rule_id: str, _: None = Depends(require_ops_key)):
    row = db.get_rule(rule_id)
    if not row:
        raise HTTPException(404, "rule_not_found")
    db.set_rule_state(rule_id, state="disabled", enabled=False, now=now())
    return {"ok": True, "state": "disabled"}


@app.post("/v1/ops/rules/simulate")
def simulate_rules(body: dict, _: None = Depends(require_ops_key)):
    events = body.get("events") or []
    rules = body.get("rules") or []
    out = []
    for ev in events:
        now_iso = now()
        ctx = {
            "campaign_id": (ev.get("traced") or {}).get("campaign_id"),
            "deployment_id": (ev.get("traced") or {}).get("deployment_id"),
            "relay_id": (ev.get("traced") or {}).get("relay_id"),
            "provider_instance_id": (ev.get("traced") or {}).get("provider_instance_id"),
            "source_ip": (ev.get("source") or {}).get("ip"),
        }
        actions = rules_engine.evaluate(event=ev, ctx=ctx, rules=rules, now=now_iso)
        out.append({"actions": actions})
    return {"ok": True, "results": out}


@app.get("/v1/ops/rules/audit")
def get_rule_audit(since: str | None = None, rule_id: str | None = None, campaign_id: str | None = None, limit: int = 200, _: None = Depends(require_ops_key)):
    rows = db.list_rule_audit(since=since, rule_id=rule_id, campaign_id=campaign_id, limit=limit)
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "at": r["at"],
            "rule_id": r["rule_id"],
            "matched": bool(int(r["matched"])),
            "fired": bool(int(r["fired"])),
            "reason": json.loads(r["reason_json"]),
            "actions": json.loads(r["actions_json"]),
            "event_ref": r["event_ref"],
            "campaign_id": r["campaign_id"],
            "provider_instance_id": r["provider_instance_id"],
            "source_ip": r["source_ip"],
        })
    return {"ok": True, "audit": out}
@app.post("/v1/integrations/canary/webhook", dependencies=[Depends(require_edge_key)])
def canary_webhook(payload: dict, user_agent: str | None = Header(default=None), x_forwarded_for: str | None = Header(default=None)):
    provider_token_id = _extract_canarytoken_id(payload)
    if not provider_token_id:
        raise HTTPException(400, "missing_canarytoken_id")

    token = db.get_token_by_provider_id("canary", provider_token_id)
    if not token:
        raise HTTPException(404, "unknown_token")

    corr = token["correlation_id"]
    hit_at = now().isoformat()
    source_ip = (x_forwarded_for.split(",")[0].strip() if x_forwarded_for else None)

    db.record_token_hit(
        id=new_id(),
        correlation_id=corr,
        provider="canary",
        provider_token_id=provider_token_id,
        source_ip=source_ip,
        user_agent=user_agent,
        raw_json=payload,
        created_at=hit_at,
    )
    db.bump_token_hit(corr, hit_at)

    if syslog:
        doc = ecs_doc(
            action="token.hit",
            correlation_id=corr,
            message="provider token triggered",
            provider="canary",
            kind=token["kind"],
            campaign_id=token["campaign_id"],
            agent_id=token["agent_id"],
            source_ip=source_ip,
            user_agent=user_agent,
        )
        syslog.send(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))

    _auto_expand_after_hit(token)

    pusher.push_canary_fire(
        campaign_id=token["campaign_id"],
        source=source_ip or "",
        user_agent=user_agent or "",
        metadata={"token_id": provider_token_id, "correlation_id": corr, "kind": token["kind"]},
    )

    return {"ok": True, "correlation_id": corr}

def main():
    import uvicorn
    uvicorn.run("controller.app:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8443")), reload=False)

if __name__ == "__main__":
    main()

def _retention_worker():
    import time
    while True:
        try:
            if EVENT_RETENTION_DAYS > 0:
                cutoff = (datetime.utcnow() - timedelta(days=EVENT_RETENTION_DAYS)).replace(microsecond=0).isoformat() + "Z"
                db.purge_events_older_than(cutoff)
        except Exception:
            pass
        time.sleep(max(60, EVENT_RETENTION_SWEEP_SEC))

@app.on_event("startup")
def _on_startup():
    import threading
    t = threading.Thread(target=_retention_worker, daemon=True)
    t.start()

