from __future__ import annotations
import os, time, random, requests, json, platform as _platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List

from agent.signing import verify
from agent.state import State
from agent.telemetry import ECSTelemetry
from agent.plugins.docker_workload import DockerWorkload, docker_available
from agent.plugins.file_artifact import FileArtifact

AGENT_ID = os.environ.get("RUNNER_ID", "agent-1")
EDGE_URL = os.environ.get("EDGE_URL")
SHARED_SECRET = os.environ.get("EDGE_SHARED_SECRET", "change-me").encode("utf-8")
EDGE_API_KEY = os.environ.get("EDGE_API_KEY", "")

POLL_BASE_SECONDS = int(os.environ.get("RUNNER_POLL_SECONDS", "300"))
AGENT_VERSION = os.environ.get("RUNNER_VERSION", "0.6.0")

BASE_DIR = Path(os.environ.get("RUNNER_BASE_DIR", str(Path.home() / ".cache" / "runner")))
STATE_PATH = os.environ.get("RUNNER_STATE_PATH", str(BASE_DIR / "state.json"))

LOG_MODE = os.environ.get("RUNNER_LOG_MODE", "edge_then_so")
SO_HOST = os.environ.get("RUNNER_SO_HOST", "127.0.0.1")
SO_PORT = int(os.environ.get("RUNNER_SO_PORT", "514"))
SO_PROTO = os.environ.get("RUNNER_SO_PROTO", "udp")

workloads = {
    "docker_workload": DockerWorkload(),
    "file_artifact": FileArtifact(),
}

_last_edge_log_ok: bool | None = None
_last_edge_log_at: str | None = None

def _headers() -> Dict[str, str]:
    if not EDGE_API_KEY:
        return {}
    return {"Authorization": f"Bearer {EDGE_API_KEY}"}

def _now_iso() -> str:
    return datetime.utcnow().isoformat()

def main():
    if not EDGE_URL:
        raise SystemExit("Set EDGE_URL")

    BASE_DIR.mkdir(parents=True, exist_ok=True)
    st = State(str(STATE_PATH))

    tel = ECSTelemetry(
        service_name="svc-runner",
        transport=("syslog" if LOG_MODE in ("direct_so", "both") else "stdout"),
        syslog_host=SO_HOST,
        syslog_port=SO_PORT,
        syslog_proto=SO_PROTO,
    )

    while True:
        try:
            jobs = pull_jobs(st)
            for job in jobs:
                handle(job, st, tel)
        except Exception:
            pass
        # jitter ±20% around base interval to avoid predictable beaconing
        jitter = random.uniform(-0.20, 0.20)
        sleep_secs = int(POLL_BASE_SECONDS * (1 + jitter))
        time.sleep(sleep_secs)

def pull_jobs(st: State) -> List[Dict[str, Any]]:
    body = {
        "agent_id": AGENT_ID,
        "state_hash": st.state_hash(),
        "max_jobs": 10,
        "platform": f"{_platform.system().lower()}-{_platform.machine()}",
        "version": AGENT_VERSION,
        "caps": {"docker": bool(docker_available())},
        "logging": {
            "mode": LOG_MODE,
            "last_edge_log_ok": _last_edge_log_ok,
            "last_edge_log_at": _last_edge_log_at,
        },
    }
    r = requests.post(f"{EDGE_URL}/v1/agents/checkin", headers=_headers(), json=body, timeout=10)
    r.raise_for_status()
    return r.json()


def _is_expired(expires_at: str) -> bool:
    """Parse controller timestamp (may carry a trailing 'Z') and compare in aware UTC."""
    try:
        raw = expires_at.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > dt
    except Exception:
        # Fail closed: if we cannot parse expiry, treat the job as expired.
        return True

def handle(job: Dict[str, Any], st: State, tel: ECSTelemetry) -> None:
    job_id = job["job_id"]
    if st.job_done(job_id):
        return

    env = {
        "relay_id": job["relay_id"],
        "action": job["action"],
        "issued_at": job["issued_at"],
        "expires_at": job["expires_at"],
        "payload": job["payload"],
    }
    if not verify(SHARED_SECRET, env, job["signature"]):
        post_result(job_id, ok=False, detail="bad_signature", metadata={})
        st.mark_job_done(job_id); st.save()
        return

    if _is_expired(job["expires_at"]):
        post_result(job_id, ok=False, detail="expired_job", metadata={})
        st.mark_job_done(job_id); st.save()
        return

    ok, detail, meta = True, "ok", {}

    try:
        payload = job["payload"] or {}
        action = job["action"]

        if action == "apply":
            for w in payload.get("workloads") or []:
                if w.get("agent_id") != AGENT_ID:
                    continue

                wtype = w["workload_type"]
                wid = w["workload_id"]
                cfg = w.get("cfg") or {}

                plugin = workloads.get(wtype)
                if not plugin:
                    continue

                current = st.get_dep("w", wid)
                cfg_hash = _cfg_hash(cfg)
                if current and current.get("cfg_hash") == cfg_hash:
                    continue
                cfg = dict(cfg)
                cfg["cfg_hash"] = cfg_hash

                dep = plugin.apply(base_dir=BASE_DIR, workload_id=wid, cfg=cfg) if wtype == "docker_workload" else plugin.apply(workload_id=wid, cfg=cfg)

                if dep:
                    st.set_dep("w", wid, dep)
                    st.save()
                    doc = tel.doc(action="workload.start", message="workload applied", correlation_id=wid, extra={"kind": dep.get("kind","")})
                    send_log(doc, tel)

        elif action == "remove":
            for key, dep in list(st.data["deployments"].items()):
                if not key.startswith("w:"):
                    continue
                wid = key.split(":", 1)[1]
                wtype = dep.get("workload_type")
                plugin = workloads.get(wtype)
                if plugin:
                    plugin.remove(dep)
                st.del_dep("w", wid)
                st.save()
                doc = tel.doc(action="workload.stop", message="workload removed", correlation_id=wid)
                send_log(doc, tel)
        else:
            ok = False
            detail = f"unknown_action:{action}"

    except Exception as e:
        ok = False
        detail = f"exception:{type(e).__name__}"
        meta = {"error": str(e)[:1500]}

    post_result(job_id, ok=ok, detail=detail, metadata=meta)
    st.mark_job_done(job_id); st.save()

def _cfg_hash(cfg: Dict[str, Any]) -> str:
    import hashlib, json
    raw = json.dumps(cfg, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def post_result(job_id: str, *, ok: bool, detail: str, metadata: Dict[str, Any]) -> None:
    try:
        requests.post(
            f"{EDGE_URL}/v1/agents/job_results",
            headers=_headers(),
            json={"job_id": job_id, "agent_id": AGENT_ID, "ok": ok, "detail": detail, "metadata": metadata},
            timeout=10,
        )
    except Exception:
        pass

def send_log(doc: Dict[str, Any], tel: ECSTelemetry) -> None:
    global _last_edge_log_ok, _last_edge_log_at
    mode = LOG_MODE.lower()
    sent = False

    if mode in ("edge_then_so", "both"):
        _last_edge_log_at = _now_iso()
        try:
            r = requests.post(f"{EDGE_URL}/v1/agents/logs", headers=_headers(), json={"ecs": doc}, timeout=5)
            _last_edge_log_ok = bool(r.ok)
            sent = bool(r.ok)
        except Exception:
            _last_edge_log_ok = False

    if mode in ("direct_so", "both"):
        tel.emit(doc)
        sent = True

    if not sent:
        print(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))

if __name__ == "__main__":
    main()
