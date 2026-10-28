from __future__ import annotations
import json, socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

class SyslogForwarder:
    def __init__(self, host: str, port: int = 514, proto: str = "udp"):
        self.host = host
        self.port = port
        self.proto = proto.lower()

    def send(self, line: str) -> None:
        data = line.encode("utf-8", errors="replace")
        if self.proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, (self.host, self.port))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                s.sendall(data + b"\n")

def ecs_doc(
    *,
    action: str,
    correlation_id: str,
    message: str,
    outcome: str = "success",
    provider: str | None = None,
    kind: str | None = None,
    campaign_id: str | None = None,
    agent_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    extra_labels: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    d: Dict[str, Any] = {
        "@timestamp": ts,
        "message": message,
        "event": {
            "kind": "event",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "action": action,
            "outcome": outcome,
        },
        "service": {"name": "controller"},
        "labels": {"correlation_id": correlation_id},
    }

    if provider:
        d["labels"]["provider"] = provider
    if kind:
        d["labels"]["kind"] = kind
    if campaign_id:
        d["labels"]["campaign_id"] = campaign_id
    if agent_id:
        d["labels"]["agent_id"] = agent_id
    if source_ip:
        d["source"] = {"ip": source_ip}
    if user_agent:
        d["user_agent"] = {"original": user_agent}
    if extra_labels:
        for k, v in extra_labels.items():
            d["labels"][k] = str(v)

    return d
