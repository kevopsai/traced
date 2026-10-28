from __future__ import annotations
import json, hashlib
from pathlib import Path
from typing import Any, Dict, Optional

class State:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.data = {"deployments": {}, "jobs_done": {}}

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")

    def state_hash(self) -> str:
        raw = json.dumps(self.data.get("deployments", {}), separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def job_done(self, job_id: str) -> bool:
        return bool(self.data.get("jobs_done", {}).get(job_id))

    def mark_job_done(self, job_id: str) -> None:
        self.data.setdefault("jobs_done", {})[job_id] = True

    def get_dep(self, kind: str, dep_id: str) -> Optional[Dict[str, Any]]:
        return self.data.get("deployments", {}).get(f"{kind}:{dep_id}")

    def set_dep(self, kind: str, dep_id: str, value: Dict[str, Any]) -> None:
        self.data.setdefault("deployments", {})[f"{kind}:{dep_id}"] = value

    def del_dep(self, kind: str, dep_id: str) -> None:
        self.data.get("deployments", {}).pop(f"{kind}:{dep_id}", None)
