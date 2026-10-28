from __future__ import annotations
import json, socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional

class ECSTelemetry:
    def __init__(self, *, service_name: str, transport: str = "stdout",
                 syslog_host: str = "127.0.0.1", syslog_port: int = 514, syslog_proto: str = "udp"):
        self.service_name = service_name
        self.transport = transport
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.syslog_proto = syslog_proto.lower()

    def doc(self, *, action: str, message: str, correlation_id: str, outcome: str = "success", extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        d: Dict[str, Any] = {
            "@timestamp": ts,
            "message": message,
            "event": {"kind": "event", "category": ["process"], "type": ["info"], "action": action, "outcome": outcome},
            "service": {"name": self.service_name},
            "labels": {"correlation_id": correlation_id},
        }
        if extra:
            d["labels"].update({k: str(v) for k, v in extra.items()})
        return d

    def emit(self, doc: Dict[str, Any]) -> None:
        line = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
        if self.transport == "syslog":
            self._syslog(line)
        else:
            print(line)

    def _syslog(self, line: str) -> None:
        data = line.encode("utf-8", errors="replace")
        if self.syslog_proto == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, (self.syslog_host, self.syslog_port))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.syslog_host, self.syslog_port))
                s.sendall(data + b"\n")
