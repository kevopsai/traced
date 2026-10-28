from __future__ import annotations
import os, subprocess, json
from pathlib import Path
from typing import Any, Dict, Optional

def docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return r.returncode == 0
    except Exception:
        return False

class DockerWorkload:
    def apply(self, *, base_dir: Path, workload_id: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not docker_available():
            raise RuntimeError("docker_not_available")

        image = cfg.get("image")
        if not image:
            raise ValueError("missing image")

        name = cfg.get("name") or f"svc-{workload_id.lower()}"
        args = ["docker", "run", "-d", "--restart", "unless-stopped", "--name", name]

        for p in (cfg.get("ports") or []):
            args += ["-p", str(p)]
        for e in (cfg.get("env") or {}).items():
            k, v = e
            args += ["-e", f"{k}={v}"]

        args.append(image)
        cmd = cfg.get("cmd")
        if isinstance(cmd, list) and cmd:
            args += cmd

        subprocess.run(["docker", "pull", image], check=False)
        r = subprocess.run(args, capture_output=True, text=True, check=False)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip()[:400])

        cid = r.stdout.strip()
        return {"kind": "docker", "workload_type": "docker_workload", "workload_id": workload_id, "container_id": cid, "name": name, "cfg_hash": cfg.get("cfg_hash","")}

    def remove(self, dep: Dict[str, Any]) -> None:
        name = dep.get("name")
        if not name:
            return
        subprocess.run(["docker", "rm", "-f", name], check=False)
