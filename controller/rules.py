from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any, List, Tuple




def dot_get(d: dict, path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def stable_hash(obj: Any) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b).hexdigest()


@dataclass(frozen=True)
class Guardrails:
    # budgets / caps
    max_actions_per_source_per_10m: int = 10
    max_tokens_per_campaign_per_day: int = 20
    max_state_updates_per_provider_per_10m: int = 5
    max_deploys_per_campaign_per_hour: int = 10

    # dedupe
    dedupe_window_sec: int = 600

    # circuit breaker (observe-only)
    breaker_events_per_minute: int = 500
    breaker_hold_sec: int = 1800  # 30m


def _rolling_add(state: dict, now_iso: str, limit: int = 2048) -> dict:
    ts = list(state.get("ts", []))
    ts.append(now_iso)
    if len(ts) > limit:
        ts = ts[-limit:]
    state["ts"] = ts
    return state


def _budget_key(prefix: str, *parts: str) -> str:
    return prefix + "|" + "|".join([p for p in parts if p])


def _intent_hash(action: dict, ctx: dict) -> str:
    intent = {
        "type": action.get("type"),
        "campaign_id": ctx.get("campaign_id"),
        "provider_instance_id": ctx.get("provider_instance_id"),
        "source_ip": ctx.get("source_ip"),
        "provider_id": action.get("provider_id"),
        "kind": action.get("kind"),
        "template": action.get("template"),
        "patch": action.get("patch"),
    }
    return stable_hash(intent)


class RulesEngine:
    def __init__(self, *, db, guardrails: Guardrails, emit_alert):
        self.emit_alert = emit_alert
        self.db = db
        self.guard = guardrails

    def evaluate(self, *, event: dict, ctx: dict, rules: list[dict], now: str) -> list[dict]:
        dispatched: list[dict] = []
        for rule in rules:
            rid = rule.get("id", "")
            if not rid or not rule.get("enabled", True):
                continue

            matched, m_reason = self._match(rule, event, ctx)
            fired = False
            actions: list[dict] = []
            blocked_reasons: list[str] = []

            if matched:
                ok_gate, gate_reason = self._gate(rule, event, ctx, now)
                if not ok_gate:
                    blocked_reasons.append(gate_reason)
                else:
                    actions = self._render_actions(rule.get("actions", []))
                    actions, blocked = self._apply_guardrails(actions, event, ctx, now)
                    blocked_reasons.extend(blocked)
                    if actions:
                        fired = True
                        dispatched.extend(actions)

                        self.emit_alert({
                            "event": {
                                "kind": "alert",
                                "category": ["intrusion_detection"],
                                "type": ["info"],
                                "action": "rule_fired",
                                "outcome": "success",
                            },
                            "rule": {"id": rid, "name": rule.get("name", rid)},
                            "traced": {k: v for k, v in {
                                "campaign_id": ctx.get("campaign_id"),
                                "deployment_id": ctx.get("deployment_id"),
                                "relay_id": ctx.get("relay_id"),
                                "provider_instance_id": ctx.get("provider_instance_id"),
                            }.items() if v},
                            "source": {"ip": ctx.get("source_ip")} if ctx.get("source_ip") else {},
                            "message": f"Rule fired: {rule.get('name', rid)}",
                            "traced_actions": actions,
                        })

            audit_id = str(uuid.uuid4())
            event_ref = stable_hash({"ts": dot_get(event, "@timestamp"), "h": stable_hash(event)[:16]})
            reason_out = {"match": m_reason, "blocked": blocked_reasons}
            self.db.insert_rule_audit(
                id=audit_id, at=now, rule_id=rid,
                matched=matched, fired=fired,
                reason=reason_out, actions=actions,
                event_ref=event_ref,
                campaign_id=ctx.get("campaign_id"),
                provider_instance_id=ctx.get("provider_instance_id"),
                source_ip=ctx.get("source_ip"),
            )
        return dispatched

    def _match(self, rule: dict, event: dict, ctx: dict) -> Tuple[bool, dict]:
        match = rule.get("match") or {}
        for k, v in match.items():
            actual = dot_get(event, k)
            if actual is None:
                actual = ctx.get(k)
            if isinstance(v, list):
                if actual not in v:
                    return False, {"field": k, "need": v, "got": actual}
            else:
                if actual != v:
                    return False, {"field": k, "need": v, "got": actual}
        return True, {"fields": list(match.keys())}

    def _gate(self, rule: dict, event: dict, ctx: dict, now: str) -> Tuple[bool, str]:
        rid = rule["id"]
        scope = rule.get("scope", "global")
        group_by = rule.get("group_by") or []
        gb_parts = []
        for f in group_by:
            val = dot_get(event, f) or ctx.get(f) or ""
            gb_parts.append(f"{f}={val}")

        parts = [f"rid={rid}", f"scope={scope}"]
        if ctx.get("campaign_id"):
            parts.append(f"c={ctx['campaign_id']}")
        if scope == "provider_instance" and ctx.get("provider_instance_id"):
            parts.append(f"pi={ctx['provider_instance_id']}")
        parts.extend(gb_parts)
        key = _budget_key("rulefire", *parts)

        cooldown = int(rule.get("cooldown_sec") or 0)
        max_triggers = int(rule.get("max_triggers") or 0)

        # cooldown marker
        if cooldown:
            if self.db.kv_get(key + "|cd"):
                return False, "cooldown"

        # threshold (rolling count approximation)
        thr = rule.get("threshold")
        if thr:
            window = int(thr.get("window_sec", 60))
            need = int(thr.get("count", 1))
            ckey = key + "|cnt"
            st = self.db.kv_get(ckey) or {"ts": []}
            st = _rolling_add(st, now)
            self.db.kv_set(ckey, st, ttl_sec=window + 30)
            if len(st.get("ts", [])) < need:
                return False, f"threshold({len(st.get('ts', []))}/{need})"

        # max triggers stored in main key
        st2 = self.db.kv_get(key) or {"fires": 0}
        if max_triggers and int(st2.get("fires", 0)) >= max_triggers:
            return False, "max_triggers"

        st2["fires"] = int(st2.get("fires", 0)) + 1
        st2["last_fire"] = now
        self.db.kv_set(key, st2, ttl_sec=7 * 24 * 3600)
        if cooldown:
            self.db.kv_set(key + "|cd", {"x": 1}, ttl_sec=cooldown)
        return True, "ok"

    def _render_actions(self, actions: list[dict]) -> list[dict]:
        return [a for a in actions if isinstance(a, dict) and a.get("type")]

    def _apply_guardrails(self, actions: list[dict], event: dict, ctx: dict, now: str) -> Tuple[list[dict], list[str]]:
        blocked: list[str] = []
        if not actions:
            return actions, blocked

        # circuit breaker by provider_instance_id (event storm)
        pi = ctx.get("provider_instance_id") or ""
        if pi:
            ek = _budget_key("evrate60", pi)
            est = self.db.kv_get(ek) or {"ts": []}
            est = _rolling_add(est, now)
            self.db.kv_set(ek, est, ttl_sec=90)

            brk_key = _budget_key("breaker", pi)
            if self.db.kv_get(brk_key):
                actions2 = [a for a in actions if a.get("type") == "notify"]
                if len(actions2) != len(actions):
                    blocked.append("breaker_active")
                actions = actions2
            elif len(est.get("ts", [])) >= self.guard.breaker_events_per_minute:
                self.db.kv_set(brk_key, {"since": now, "count": len(est.get("ts", []))}, ttl_sec=self.guard.breaker_hold_sec)
                actions2 = [a for a in actions if a.get("type") == "notify"]
                if len(actions2) != len(actions):
                    blocked.append("breaker_tripped")
                actions = actions2

        # per-source cap (10m)
        src = ctx.get("source_ip") or ""
        if src:
            bk = _budget_key("src10m", src)
            st = self.db.kv_get(bk) or {"ts": []}
            st = _rolling_add(st, now)
            self.db.kv_set(bk, st, ttl_sec=660)
            if len(st.get("ts", [])) > self.guard.max_actions_per_source_per_10m:
                blocked.append("budget_src_10m")
                actions = [a for a in actions if a.get("type") == "notify"]

        # per-provider update cap (10m)
        if pi:
            upd = [a for a in actions if a.get("type") == "update_provider_state"]
            if upd:
                bk = _budget_key("pi_upd10m", pi)
                st = self.db.kv_get(bk) or {"ts": []}
                for _ in upd:
                    st = _rolling_add(st, now)
                self.db.kv_set(bk, st, ttl_sec=660)
                if len(st.get("ts", [])) > self.guard.max_state_updates_per_provider_per_10m:
                    blocked.append("budget_pi_upd_10m")
                    actions = [a for a in actions if a.get("type") != "update_provider_state"]

        # intent dedupe
        deduped: list[dict] = []
        for a in actions:
            ih = _intent_hash(a, ctx)
            dk = _budget_key("dedupe", ih)
            if self.db.kv_get(dk):
                blocked.append("dedupe")
                continue
            self.db.kv_set(dk, {"at": now}, ttl_sec=self.guard.dedupe_window_sec)
            deduped.append(a)
        return deduped, blocked


def emit_rule_alert(db, forwarder, alert: dict) -> None:
    # Persist + optional forward
    db.insert_event("alert", alert)
    try:
        if forwarder.enabled_for("alert"):
            forwarder.send_syslog_json(alert)
    except Exception:
        pass
