from __future__ import annotations
import os, requests

CANARY_API_BASE = os.environ.get("CANARY_API_BASE", "").rstrip("/")
CANARY_AUTH_TOKEN = os.environ.get("CANARY_AUTH_TOKEN", "")
CANARY_FLOCK_ID = os.environ.get("CANARY_FLOCK_ID", "flock:default")

class CanaryProvider:
    name = "canary"

    def __init__(self):
        if not CANARY_API_BASE or not CANARY_AUTH_TOKEN:
            raise RuntimeError("CANARY_API_BASE and CANARY_AUTH_TOKEN required")

    def create(self, *, kind: str, memo: str) -> dict:
        url = f"{CANARY_API_BASE}/api/v1/canarytoken/create"
        r = requests.post(
            url,
            data={
                "auth_token": CANARY_AUTH_TOKEN,
                "flock_id": CANARY_FLOCK_ID,
                "kind": kind,
                "memo": memo,
            },
            timeout=20,
        )
        r.raise_for_status()
        j = r.json()
        if j.get("result") != "success":
            raise RuntimeError(f"canary_create_failed:{j}")
        return j["canarytoken"]

    def download(self, *, provider_token_id: str) -> tuple[str, bytes]:
        url = f"{CANARY_API_BASE}/api/v1/canarytoken/download"
        r = requests.get(
            url,
            params={"auth_token": CANARY_AUTH_TOKEN, "canarytoken": provider_token_id},
            allow_redirects=True,
            timeout=30,
        )
        r.raise_for_status()

        cd = r.headers.get("Content-Disposition", "")
        filename = "canarytoken.bin"
        if "filename=" in cd:
            filename = cd.split("filename=", 1)[1].strip().strip('"')
        return filename, r.content
