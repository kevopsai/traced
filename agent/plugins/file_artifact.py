from __future__ import annotations
import base64
from pathlib import Path
from typing import Any, Dict, Optional

class FileArtifact:
    def apply(self, *, workload_id: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw_path = cfg.get("path")
        if not raw_path:
            raise ValueError("missing path")

        p = Path(raw_path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)

        if "content_b64" in cfg:
            data = base64.b64decode(cfg["content_b64"])
            p.write_bytes(data)
        else:
            content = cfg.get("content", "")
            p.write_text(content, encoding="utf-8")

        mode = cfg.get("mode")
        if mode:
            try:
                p.chmod(int(mode, 8))
            except Exception:
                pass

        return {"kind": "file", "workload_type": "file_artifact", "workload_id": workload_id, "path": str(p), "cfg_hash": cfg.get("cfg_hash","")}

    def remove(self, dep: Dict[str, Any]) -> None:
        path = dep.get("path")
        if not path:
            return
        p = Path(path).expanduser()
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass
