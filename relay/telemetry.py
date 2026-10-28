from __future__ import annotations
import socket

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
