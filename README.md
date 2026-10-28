# TRACED — Deception System

TRACED is a lightweight deception and canarytoken orchestration platform designed for red team and threat detection engagements. It deploys instrumented lures (file artifacts, canary tokens) onto target hosts via a distributed agent fleet, then monitors and correlates trigger events to detect adversary activity.

## How it works

The system has three components that work together:

```
Operator (ops API)
      │
      ▼
┌─────────────┐       poll/checkin       ┌─────────────┐       poll/checkin       ┌─────────────┐
│  Controller │ ◄──────────────────────► │    Relay    │ ◄──────────────────────► │    Agent    │
│  (port 8443)│                          │  (port 9443)│                          │  (host)     │
└─────────────┘                          └─────────────┘                          └─────────────┘
      │                                        │
      │  ECS events / canary webhooks          │  ECS events → syslog
      ▼                                        ▼
 SQLite DB                              Security Onion
 Rules engine                           (optional SIEM)
 Alerts
```

**Controller** — the brains. Manages campaigns, objects, tokens, and the relay/agent fleet. Accepts canary webhook callbacks, evaluates detection rules, and raises alerts. Exposes an ops API for campaign lifecycle management.

**Relay** — a lightweight edge node that sits closer to targets. Buffers jobs for agents, accepts agent checkins and results, and forwards ECS telemetry upstream to the controller and optionally to Security Onion via syslog. Can be deployed as a systemd appliance via `bootstrap-relay.sh`.

**Agent** — runs on target hosts (or attacker-controlled machines during simulation). Polls the relay for jobs, executes workloads (file artifact drops, Docker containers), and emits ECS-format logs back through the relay.

## Workload types

| Type | What it does |
|---|---|
| `file_artifact` | Drops a lure file on the host at a specified path with configurable content and permissions |
| `docker_workload` | Spins up a Docker container as a workload (e.g. a honeyservice) |

## Campaign lifecycle

1. **Create** a campaign with a name, objective, and tags
2. **Add objects** — lures and tokens associated with the campaign
3. **Deploy** — push jobs to agents via a relay
4. **Monitor** — canary webhooks and agent telemetry flow back and trigger alerts
5. **Teardown** — clean up deployed artifacts from target agents
6. **Purge** — wipe campaign events and rule state from the database

## Token integration

TRACED integrates with [Canarytokens](https://canarytokens.org) to generate and embed tokens within lure artifacts. When a token is triggered, the canary webhook fires to the controller (`/v1/integrations/canary/webhook`), which correlates the hit to the originating campaign and agent, evaluates rules, and raises an alert.

## Telemetry & SIEM

All events are ECS-formatted JSON. The relay forwards events to Security Onion (or any syslog receiver) over UDP/TCP. The controller can also forward token-hit events independently. Both are optional — events are always stored in SQLite regardless.

## Authentication

| Key | Used by |
|---|---|
| `OPS_API_KEY` | Operator → Controller (campaign management, fleet status) |
| `EDGE_API_KEY` | Relay → Controller and Agent → Relay |
| `TRACED_SHARED_SECRET` | HMAC envelope signing between all components |

## Security posture

- All inter-component communication is HMAC-signed
- API keys support a `_PREV` rotation variant for zero-downtime key rotation
- Guardrails enforce rate limits on token creation, deployments, and event ingestion to prevent runaway operations
- Circuit breaker on event ingestion (configurable events/min threshold)

---

## Quick start (controller + relay)

1. Copy env:
```bash
cp .env.example .env
# edit .env — set real values for all keys
```

2. Start:
```bash
docker compose --env-file .env up -d --build
```

3. Verify:
```bash
curl -sS http://localhost:8443/v1/status
curl -sS http://localhost:9443/v1/edge/poll -H "Authorization: Bearer $EDGE_API_KEY"
```

## Run agent locally (no Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r agent/requirements.txt

export EDGE_URL="http://localhost:9443"
export EDGE_API_KEY="$EDGE_API_KEY"
export EDGE_SHARED_SECRET="$TRACED_SHARED_SECRET"
export RUNNER_ID="host-01"

python -m agent.main
```

## API examples

### Create a campaign
```bash
curl -sS -X POST http://localhost:8443/v1/campaigns \
  -H "Authorization: Bearer $OPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-campaign","objective":"mvp","tags":["mvp","engage:prepare"]}' | jq .
```

### Add a file artifact lure
```bash
curl -sS -X POST http://localhost:8443/v1/campaigns/$CID/objects \
  -H "Authorization: Bearer $OPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "object_type":"file_artifact",
    "name":"budget-notes",
    "cfg":{"path":"~/Documents/budget-notes.txt","content":"Renewal notes, vendor shortlist.","mode":"0644"},
    "tags":["lure:document","engage:operate"]
  }' | jq .
```

### Deploy to agents via relay
```bash
curl -sS -X POST http://localhost:8443/v1/campaigns/$CID/deploy \
  -H "Authorization: Bearer $OPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"relay_id":"relay-1","target_agent_ids":["host-01"]}' | jq .
```

### Fleet status
```bash
curl -sS http://localhost:8443/v1/ops/status \
  -H "Authorization: Bearer $OPS_API_KEY" | jq .
```

### Campaign ops status
```bash
curl -sS http://localhost:8443/v1/campaigns/$CID/ops \
  -H "Authorization: Bearer $OPS_API_KEY" | jq .
```

### Query alerts
```bash
curl -sS http://localhost:8443/v1/ops/alerts \
  -H "Authorization: Bearer $OPS_API_KEY" | jq .
```

### Teardown
```bash
curl -sS -X POST http://localhost:8443/v1/campaigns/$CID/teardown \
  -H "Authorization: Bearer $OPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"relay_id":"relay-1","target_agent_ids":["host-01"]}' | jq .
```

### Purge campaign data
```bash
curl -sS -X POST http://localhost:8443/v1/ops/campaigns/$CID/purge \
  -H "Authorization: Bearer $OPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"purge_events": true}' | jq .
```

---

## Relay appliance install

On a relay host (Ubuntu 22.04), from the repo root:
```bash
chmod +x deploy/bootstrap-relay.sh deploy/relay_id.sh
sudo CORE_URL=http://CONTROLLER_IP:8443 \
  EDGE_API_KEY="$EDGE_API_KEY" \
  TRACED_SHARED_SECRET="$TRACED_SHARED_SECRET" \
  SO_HOST="SECURITY_ONION_IP" \
  ./deploy/bootstrap-relay.sh
```

### One-command relay enrollment

Generate an enrollment token on the controller:
```bash
curl -sS -X POST http://CONTROLLER_IP:8443/v1/ops/enroll/relay \
  -H "Authorization: Bearer $OPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "expires_minutes":60,
    "poll_seconds":15,
    "so_host":"SECURITY_ONION_IP",
    "so_port":514,
    "so_proto":"udp",
    "controller_url":"http://CONTROLLER_IP:8443"
  }' | jq .
```

Paste the returned `command` onto the relay host:
```bash
curl -fsSL "http://CONTROLLER_IP:8443/v1/enroll/relay.sh?token=TOKEN" | sudo bash
```

Label the relay:
```bash
curl -sS -X PUT http://CONTROLLER_IP:8443/v1/ops/relays/<relay_id>/label \
  -H "Authorization: Bearer $OPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"label":"Denver NUC 01"}' | jq .
```

---

## Notes

- The relay forwards ECS JSON via syslog to Security Onion (UDP by default). Configure with `EDGE_SO_HOST`, `EDGE_SO_PORT`, `EDGE_SO_PROTO`.
- The controller can also forward token-hit ECS events independently if `TRACED_SO_HOST` is set.
- Canary webhook endpoint: `POST /v1/integrations/canary/webhook` — auth with `EDGE_API_KEY`. Configure the URL in the Canary console.
- SIEM forwarding from the controller is controlled by `FWD_SYSLOG_HOST`, `FWD_SYSLOG_PORT`, `FWD_SYSLOG_PROTO`, `FWD_SYSLOG_WHAT` (`events` | `alerts` | `none`).

## License

Traced is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
