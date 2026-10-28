from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Literal, Optional
from datetime import datetime, timezone
from uuid import uuid4

def now() -> datetime:
    return datetime.now(timezone.utc)

def new_id() -> str:
    return str(uuid4())

class CampaignCreate(BaseModel):
    name: str
    objective: str = ""
    tags: List[str] = Field(default_factory=list)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None

class CampaignOut(BaseModel):
    id: str
    name: str
    objective: str
    tags: List[str] = Field(default_factory=list)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    phase: Literal["prepare", "operate", "understand"] = "prepare"
    status: Literal["draft", "scheduled", "active", "expired", "stopped"] = "draft"
    created_at: datetime

class CampaignObjectCreate(BaseModel):
    object_type: str
    name: str
    cfg: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

class CampaignObjectOut(BaseModel):
    id: str
    campaign_id: str
    object_type: str
    name: str
    cfg: Dict[str, Any]
    tags: List[str] = Field(default_factory=list)
    created_at: datetime

class DeployRequest(BaseModel):
    relay_id: str
    target_agent_ids: List[str] = Field(default_factory=list)

class JobEnvelope(BaseModel):
    job_id: str
    relay_id: str
    action: Literal["apply", "remove"]
    issued_at: datetime
    expires_at: datetime
    payload: Dict[str, Any]
    signature: str

class TokenCreate(BaseModel):
    kind: str
    agent_id: str
    relay_id: str
    placement: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

class TokenOut(BaseModel):
    correlation_id: str
    provider: str
    kind: str
    provider_token_id: str
    provider_url: Optional[str] = None
    download_name: Optional[str] = None
    agent_id: str
    relay_id: str
    hit_count: int
    last_hit_at: Optional[str] = None
    created_at: str

class CampaignStatusOut(BaseModel):
    campaign_id: str
    status: str
    starts_at: Optional[str] = None
    ends_at: Optional[str] = None
    objects: int = 0
    tokens: int = 0
    token_hits: int = 0
    last_hit_at: Optional[str] = None

class RelayCheckinIn(BaseModel):
    version: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)
    agents_seen: Optional[int] = None
    logging: Dict[str, Any] = Field(default_factory=dict)

class AgentHeartbeatIn(BaseModel):
    agent_id: str
    platform: Optional[str] = None
    version: Optional[str] = None
    caps: Dict[str, Any] = Field(default_factory=dict)
    logging: Dict[str, Any] = Field(default_factory=dict)

class OpsRelayOut(BaseModel):
    relay_id: str
    label: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)
    last_seen_at: Optional[str]
    age_sec: Optional[int]
    status: str
    version: Optional[str] = None
    agents_seen: int = 0
    logging: Dict[str, Any] = Field(default_factory=dict)

class OpsAgentOut(BaseModel):
    agent_id: str
    relay_id: Optional[str]
    last_seen_at: Optional[str]
    age_sec: Optional[int]
    status: str
    platform: Optional[str] = None
    version: Optional[str] = None
    caps: Dict[str, Any] = Field(default_factory=dict)
    logging: Dict[str, Any] = Field(default_factory=dict)

class OpsSummaryOut(BaseModel):
    relays_ok: int = 0
    relays_stale: int = 0
    agents_ok: int = 0
    agents_stale: int = 0

class OpsStatusOut(BaseModel):
    time: str
    relays: List[OpsRelayOut] = Field(default_factory=list)
    agents: List[OpsAgentOut] = Field(default_factory=list)
    summary: OpsSummaryOut

class CampaignTargetOut(BaseModel):
    relay_id: str
    agent_id: str
    targeted_at: str
    deploy_state: str
    agent_last_seen_at: Optional[str] = None
    agent_age_sec: Optional[int] = None
    last_applied_at: Optional[str] = None
    last_job_result: Optional[Dict[str, Any]] = None
    token_hits: Dict[str, Any] = Field(default_factory=dict)
    logging: Dict[str, Any] = Field(default_factory=dict)

class CampaignOpsOut(BaseModel):
    campaign_id: str
    status: str
    targets: List[CampaignTargetOut] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
