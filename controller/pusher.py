"""
controller/pusher.py — Outbound webhook push to Base44 dashboard
Fires on: canary_fire, status_update, campaign_event
"""
from __future__ import annotations
import json
import logging
import threading
import urllib.request
import urllib.error
import os

logger = logging.getLogger("traced.pusher")

DASHBOARD_WEBHOOK_URL = os.environ.get("DASHBOARD_WEBHOOK_URL", "")
DASHBOARD_WEBHOOK_SECRET = os.environ.get("DASHBOARD_WEBHOOK_SECRET", "")


def _push(payload: dict) -> None:
    """Fire-and-forget POST to the dashboard webhook. Runs in a daemon thread."""
    if not DASHBOARD_WEBHOOK_URL or not DASHBOARD_WEBHOOK_SECRET:
        return

    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        DASHBOARD_WEBHOOK_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DASHBOARD_WEBHOOK_SECRET}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.debug("pusher: %s -> %s", payload.get("type"), resp.status)
    except urllib.error.HTTPError as e:
        logger.warning("pusher: HTTP %s for type=%s", e.code, payload.get("type"))
    except Exception as e:
        logger.warning("pusher: failed type=%s err=%s", payload.get("type"), e)


def push(payload: dict) -> None:
    """Non-blocking push — spawns a daemon thread so it never blocks the request path."""
    t = threading.Thread(target=_push, args=(payload,), daemon=True)
    t.start()


# ── Convenience helpers ────────────────────────────────────────────────────────

def push_canary_fire(campaign_id: str, source: str, user_agent: str, metadata: dict) -> None:
    push({
        "type": "canary_fire",
        "campaign_id": campaign_id,
        "source": source,
        "user_agent": user_agent,
        "metadata": metadata,
    })


def push_status_update(relays: list[dict], agents: list[dict]) -> None:
    push({
        "type": "status_update",
        "relays": relays,
        "agents": agents,
    })


def push_campaign_event(campaign_id: str, event_type: str, severity: str, metadata: dict) -> None:
    push({
        "type": "campaign_event",
        "campaign_id": campaign_id,
        "event_type": event_type,
        "severity": severity,
        "metadata": metadata,
    })
