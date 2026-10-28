# TRACED — Deployment Runbook

> **Classification: Internal — Uncommon Mercenaries**
> Last updated: 2026-04-03 | Version: v0.6.0

---

## Overview

TRACED is a three-tier deception infrastructure platform.

```
[Operator] ──OPS API──▶ [Controller] ──HMAC──▶ [Relay] ──EDGE API──▶ [Agent]
```

- **Controller** — central brain. Manages campaigns, objects, signing, event log.
- **Relay** — edge distributor. Polls controller, dispatches jobs to agents, forwards results.
- **Agent** — runs on target host. Polls relay, executes plugins (file_artifact, docker_workload).

---

## Prerequisites

- Docker + Docker Compose (controller and relay)
- Python 3.11+ (agent, or compiled binary)
- Outbound HTTPS from relay to controller
- Outbound HTTPS from agent to relay

---

## 1. Controller Setup

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| TRACED_SHARED_SECRET | YES | HMAC secret shared with all relays |
| OPS_API_KEY | YES | Ops-tier API key (operator token) |
| OPS_API_KEY_PREV | no | Previous ops key (zero-downtime rotation) |
| EDGE_API_KEY | YES | Edge-tier API key (relay auth token) |
| EDGE_API_KEY_PREV | no | Previous edge key (zero-downtime rotation) |
| TRACED_CONTROLLER_DB | no | SQLite path (default: controller.db) |
| EVENT_RETENTION_DAYS | no | Event log TTL in days (default: 14) |
| EVENT_RETENTION_SWEEP_SEC | no | Sweep interval in seconds (default: 3600) |
| CANARY_API_BASE | no | Canary token API base URL |
| CANARY_AUTH_TOKEN | no | Canary API auth token |
| CANARY_FLOCK_ID | no | Canary flock ID for token placement |
| TRACED_SO_HOST | no | Syslog host for telemetry forwarding |

### Start

```bash
cp .env.example .env
# Edit .env with your values
docker compose up -d controller
```

### Verify

```bash
curl -H "Authorization: Bearer <OPS_API_KEY>" http://localhost:8443/v1/status
```

---

## 2. Relay Setup

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| EDGE_RELAY_ID | YES | Unique relay ID (e.g. relay-nyc-01) |
| EDGE_API_KEY | YES | Must match controller EDGE_API_KEY |
| EDGE_SHARED_SECRET | YES | Must match controller TRACED_SHARED_SECRET |
| CORE_URL | YES | Controller URL (e.g. https://ctrl.yourdomain.com) |
| EDGE_DB | no | SQLite path (default: relay.db) |
| EDGE_POLL_SECONDS | no | Poll interval in seconds (default: 30) |
| EDGE_SO_HOST | no | Syslog host |
| EDGE_SO_PORT | no | Syslog port (default: 514) |
| EDGE_SO_PROTO | no | udp or tcp (default: udp) |

### Start

```bash
docker compose up -d relay
```

### Verify

```bash
curl -X POST -H "Authorization: Bearer <EDGE_API_KEY>" \
  http://localhost:9443/v1/edge/poll
```

---

## 3. Agent Setup

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| EDGE_URL | YES | Relay URL (e.g. https://relay.yourdomain.com) |
| EDGE_API_KEY | YES | Must match relay EDGE_API_KEY |
| EDGE_SHARED_SECRET | YES | Must match relay EDGE_SHARED_SECRET |
| RUNNER_ID | YES | Unique agent ID (e.g. agent-target-01) |
| RUNNER_BASE_DIR | no | Working directory (default: /opt/traced) |
| RUNNER_LOG_MODE | no | stdout, syslog, or none |

### Install (systemd)

```bash
scp -r agent/ user@target:/opt/traced/
cd /opt/traced
pip install -r requirements.txt

cp deploy/traced-relay.service.tmpl /etc/systemd/system/traced-agent.service
# Set Environment= values in unit file
systemctl daemon-reload
systemctl enable --now traced-agent
```

---

## 4. Running an Engagement

### Create a campaign

```bash
curl -X POST -H "Authorization: Bearer <OPS_API_KEY>" \
  -H "Content-Type: application/json" \
  http://ctrl:8443/v1/campaigns \
  -d '{
    "name": "op-darknode",
    "objective": "Drop lure docs on target workstation",
    "tags": ["engagement:2026-q2"]
  }'
```

### Add a file artifact

```bash
curl -X POST -H "Authorization: Bearer <OPS_API_KEY>" \
  -H "Content-Type: application/json" \
  http://ctrl:8443/v1/campaigns/<CAMPAIGN_ID>/objects \
  -d '{
    "object_type": "file_artifact",
    "name": "finance-lure",
    "cfg": {
      "path": "/home/user/Documents/Q1-Budget-DRAFT.xlsx",
      "content": "<canary token embed or decoy content>",
      "mode": "0644"
    },
    "tags": ["lure:finance"]
  }'
```

### Deploy

```bash
curl -X POST -H "Authorization: Bearer <OPS_API_KEY>" \
  -H "Content-Type: application/json" \
  http://ctrl:8443/v1/campaigns/<CAMPAIGN_ID>/deploy \
  -d '{
    "relay_id": "relay-nyc-01",
    "target_agent_ids": ["agent-target-01"]
  }'
```

### Monitor ops

```bash
curl -H "Authorization: Bearer <OPS_API_KEY>" \
  http://ctrl:8443/v1/campaigns/<CAMPAIGN_ID>/ops
```

### Remove / cleanup

```bash
curl -X POST -H "Authorization: Bearer <OPS_API_KEY>" \
  http://ctrl:8443/v1/campaigns/<CAMPAIGN_ID>/remove
```

---

## 5. Key Rotation (Zero-Downtime)

1. Set OPS_API_KEY_PREV = current OPS_API_KEY
2. Set OPS_API_KEY = new key
3. Restart controller
4. Update clients to new key
5. Clear OPS_API_KEY_PREV on next rotation

Same pattern for EDGE_API_KEY / EDGE_API_KEY_PREV.

---

## 6. Firewall Requirements

### Controller host

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 8443 | TCP | Trusted IPs only | Ops API |
| 8443 | TCP | Relay IPs only | Edge API |

### Relay host

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 9443 | TCP | Agent IPs only | Agent checkin / job dispatch |

Never open controller or relay ports to 0.0.0.0. Scope all rules to known IPs.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Jobs not appearing at relay | HMAC mismatch | Verify TRACED_SHARED_SECRET matches on both sides |
| Relay poll returns empty | No pending jobs | Check campaign is deployed and relay_id matches EDGE_RELAY_ID |
| Agent gets 401 on checkin | Wrong EDGE_API_KEY | Ensure agent key matches relay EDGE_API_KEY |
| SyntaxError on controller start | Corrupted app.py | Pull latest from main (fixed in v0.6.0) |
| File not written on target | Permission denied | Check RUNNER_BASE_DIR is writable; check mode in cfg |

---

## 8. Component Versions

| Component | Language | Runtime |
|---|---|---|
| Controller | Python 3.11 | FastAPI + Uvicorn |
| Relay | Python 3.11 | FastAPI + Uvicorn |
| Agent | Python 3.11 | Standalone / systemd |
