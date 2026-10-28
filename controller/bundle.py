from __future__ import annotations
import hashlib
import io
import json
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

@dataclass(frozen=True)
class BundleManifest:
    name: str
    version: str
    sha256: str
    size_bytes: int

def _sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def build_relay_bundle(repo_root: Path, version: str) -> Tuple[bytes, BundleManifest]:
    '''
    Create a deterministic relay bundle from the controller's checked-in assets.
    Bundle layout (root of tar):
      docker-compose.yml (relay-only)
      relay/ (docker build context)
      deploy/ (systemd tmpl + scripts)
      .env.example
      README.txt
    '''
    bundle_root = repo_root / "controller" / "bundles" / "relay"
    if not bundle_root.exists():
        raise FileNotFoundError(str(bundle_root))

    include_paths = [
        (bundle_root / "docker-compose.yml", "docker-compose.yml"),
        (bundle_root / "README.txt", "README.txt"),
        (repo_root / "relay", "relay"),
        (repo_root / "deploy", "deploy"),
    ]
    env_example = repo_root / ".env.example"
    if env_example.exists():
        include_paths.append((env_example, ".env.example"))

    bio = io.BytesIO()
    # deterministic-ish: set mtime=0, uid/gid=0, uname/gname=""
    def _tar_add(t: tarfile.TarFile, src: Path, arc: str):
        if src.is_dir():
            for p in sorted(src.rglob("*")):
                if p.is_dir():
                    continue
                rel = arc + "/" + str(p.relative_to(src)).replace("\\", "/")
                _tar_add(t, p, rel)
        else:
            ti = t.gettarinfo(str(src), arcname=arc)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            with open(src, "rb") as f:
                t.addfile(ti, f)

    with tarfile.open(fileobj=bio, mode="w:gz") as t:
        for src, arc in include_paths:
            _tar_add(t, Path(src), arc)

    data = bio.getvalue()
    mani = BundleManifest(
        name="relay-bundle",
        version=version,
        sha256=_sha256(data),
        size_bytes=len(data),
    )
    return data, mani
