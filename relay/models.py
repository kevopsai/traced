from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional
from datetime import datetime, timezone

def now() -> datetime:
    return datetime.now(timezone.utc)

class JobEnvelope(BaseModel):
    job_id: str
    relay_id: str
    action: str
    issued_at: datetime
    expires_at: datetime
    payload: Dict[str, Any]
    signature: str

class AgentCheckin(BaseModel):
    agent_id: str
    state_hash: str = ""
    max_jobs: int = 10
    platform: Optional[str] = None
    version: Optional[str] = None
    caps: Dict[str, Any] = Field(default_factory=dict)
    logging: Dict[str, Any] = Field(default_factory=dict)

class AgentJobResult(BaseModel):
    job_id: str
    agent_id: str
    ok: bool
    detail: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    finished_at: datetime = Field(default_factory=now)

class AgentLog(BaseModel):
    ecs: Dict[str, Any]
