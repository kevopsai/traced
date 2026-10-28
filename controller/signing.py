from __future__ import annotations
import base64, hashlib, hmac, json
from typing import Any, Dict

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def sign(secret: bytes, envelope: Dict[str, Any]) -> str:
    msg = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64u(hmac.new(secret, msg, hashlib.sha256).digest())

def verify(secret: bytes, envelope: Dict[str, Any], signature: str) -> bool:
    expected = sign(secret, envelope)
    return hmac.compare_digest(expected, signature)
