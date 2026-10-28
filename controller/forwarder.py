from __future__ import annotations
import json
import os
import socket
from typing import Any, Dict, Optional

_FORWARD_HOST = os.environ.get("FWD_SYSLOG_HOST", "").strip()
_FORWARD_PORT = int(os.environ.get("FWD_SYSLOG_PORT", "514"))
_FORWARD_PROTO = os.environ.get("FWD_SYSLOG_PROTO", "udp").strip().lower()
_FORWARD_WHAT = os.environ.get("FWD_SYSLOG_WHAT", "events").strip().lower()  # events|alerts|none

def enabled_for(kind: str) -> bool:
    if not _FORWARD_HOST or _FORWARD_WHAT in ("none", ""):
        return False
    if _FORWARD_WHAT == "events":
        return kind in ("event", "alert")
    if _FORWARD_WHAT == "alerts":
        return kind == "alert"
    return False

def send_syslog_json(obj: Dict[str, Any]) -> None:
    if not _FORWARD_HOST:
        return
    msg = json.dumps(obj, separators=(",", ":")).encode("utf-8", errors="ignore")
    if _FORWARD_PROTO == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((_FORWARD_HOST, _FORWARD_PORT))
            s.sendall(msg + b"\n")
        finally:
            try: s.close()
            except Exception: pass
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(msg, (_FORWARD_HOST, _FORWARD_PORT))
        finally:
            try: s.close()
            except Exception: pass
