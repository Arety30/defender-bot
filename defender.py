"""
Defender Bot — authorization-boundary defense engine.

A self-contained, dependency-free engine that ingests normalized HTTP request
events, correlates behavior across a session/source over time, decides a
proportionate defensive response, and emits structured incident records.

Design goals (from the Round 2 briefing):
  * Detect auth anomalies, authz violations, enumeration, probing, session &
    token abnormalities, and unusual request sequences.
  * Respond proportionately: allow -> monitor -> rate-limit -> challenge (re-auth)
    -> invalidate session -> temp block -> reject.  Never destroy data.
  * Distinguish *authorized* security testing from *dangerous* behavior: the goal
    is to prevent unauthorized ACCESS to protected resources, not to block every
    unusual request.
  * Adaptive: correlate across requests, track evasion (source rotation with a
    stable behavioral fingerprint), and re-assess as evidence accumulates.
  * Log every significant defensive event with the required fields.

The engine is transport-agnostic: feed it dict events from a WSGI/ASGI hook,
an access log tail, or a replay file.  See `demo.py` for a runnable example.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
#  Event model
# --------------------------------------------------------------------------- #
@dataclass
class Event:
    """A single normalized request observation.

    `ts` is a monotonic float (seconds). The engine never calls the clock
    itself — the caller supplies time — so replays are deterministic.
    """
    ts: float
    source: str                 # session id, API key, or source-IP fingerprint
    method: str
    endpoint: str               # normalized route, e.g. /api/users/{id}
    raw_path: str = ""          # concrete path, e.g. /api/users/1007
    status: int = 0             # HTTP status the app returned (0 = not yet served)
    authenticated: bool = False
    auth_failed: bool = False   # credential check ran and failed
    user_id: Optional[str] = None      # the identity the request claims/uses
    owner_id: Optional[str] = None      # the identity that owns the target object
    token: Optional[str] = None
    token_valid: bool = True
    token_alg: Optional[str] = None     # e.g. "HS256", "none"
    protected: bool = False     # endpoint requires authorization
    fingerprint: str = ""       # UA/client fingerprint for cross-source linking
    extra: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
#  Response taxonomy — ordered by severity so we can escalate monotonically.
# --------------------------------------------------------------------------- #
class Action(IntEnum):
    ALLOW = 0
    MONITOR = 1          # allow, but raise scrutiny / log
    RATE_LIMIT = 2       # slow the source down
    CHALLENGE = 3        # require re-authentication / step-up
    INVALIDATE = 4       # kill the suspicious session/token
    TEMP_BLOCK = 5       # short cool-down block of the pattern
    REJECT = 6           # reject this specific request

    @property
    def label(self) -> str:
        return self.name.lower().replace("_", "-")


@dataclass
class Finding:
    kind: str            # detector slug, e.g. "authz-idor"
    confidence: float    # 0..1
    reason: str
    recommend: Action
    successful: bool     # did the probe appear to SUCCEED (reach the resource)?


# --------------------------------------------------------------------------- #
#  Per-source rolling state
# --------------------------------------------------------------------------- #
class SourceState:
    def __init__(self, source: str, window: float = 60.0):
        self.source = source
        self.window = window
        self.events: Deque[Event] = deque()
        self.auth_failures: Deque[float] = deque()
        self.seen_objects: set[str] = set()          # for enumeration detection
        self.distinct_404: Deque[float] = deque()     # probing for hidden routes
        self.threat_score: float = 0.0                # decays over time
        self.last_ts: float = 0.0
        self.reauth_pending: bool = False
        self.invalidated: bool = False
        self.blocked_until: float = 0.0
        # A behavioral fingerprint survives source-id rotation.
        self.behavior_key: str = ""

    def prune(self, now: float) -> None:
        cutoff = now - self.window
        for dq in (self.events, self.auth_failures, self.distinct_404):
            while dq and _ts_of(dq[0]) < cutoff:
                dq.popleft()

    def decay(self, now: float, half_life: float = 120.0) -> None:
        if self.last_ts and self.threat_score > 0:
            dt = max(0.0, now - self.last_ts)
            self.threat_score *= 0.5 ** (dt / half_life)


def _ts_of(x: Any) -> float:
    return x.ts if isinstance(x, Event) else float(x)


# --------------------------------------------------------------------------- #
#  The engine
# --------------------------------------------------------------------------- #
class Defender:
    def __init__(
        self,
        *,
        window: float = 60.0,
        rate_limit: int = 40,          # requests / window before rate-limiting
        auth_fail_limit: int = 5,      # failed auths / window
        enum_limit: int = 12,          # distinct object ids / window on one route
        probe_404_limit: int = 8,      # distinct 404s / window
        block_seconds: float = 30.0,
        authorized_testers: Optional[set[str]] = None,
        incident_sink: Optional[Callable[[dict], None]] = None,
    ):
        self.window = window
        self.rate_limit = rate_limit
        self.auth_fail_limit = auth_fail_limit
        self.enum_limit = enum_limit
        self.probe_404_limit = probe_404_limit
        self.block_seconds = block_seconds
        # Authorized testers get latitude: their probing is NOT blocked outright,
        # but any request that actually reaches protected data is still stopped.
        self.authorized_testers = authorized_testers or set()
        self.sources: Dict[str, SourceState] = {}
        self.fingerprints: Dict[str, str] = {}   # behavior_key -> canonical source
        self.incidents: List[dict] = []
        self._sink = incident_sink

    # -- public API -------------------------------------------------------- #
    def observe(self, event: Event) -> dict:
        """Process one event. Returns a decision dict:
        {action, action_label, findings, incident (optional), allowed}.
        """
        st = self._state_for(event)
        st.decay(event.ts)
        st.prune(event.ts)

        # Honor an active temp-block before doing anything else.
        if event.ts < st.blocked_until:
            return self._decide(event, st, [Finding(
                kind="active-block",
                confidence=1.0,
                reason=f"source under temporary block until t={st.blocked_until:.1f}",
                recommend=Action.TEMP_BLOCK,
                successful=False,
            )])

        st.events.append(event)
        st.last_ts = event.ts
        if event.auth_failed:
            st.auth_failures.append(event.ts)
        if event.status == 404:
            st.distinct_404.append(event.ts)

        findings = self._run_detectors(event, st)
        return self._decide(event, st, findings)

    def export_incidents(self) -> List[dict]:
        return list(self.incidents)

    # -- internals --------------------------------------------------------- #
    def _state_for(self, event: Event) -> SourceState:
        # Cross-source correlation: if this source shares a behavioral
        # fingerprint with a known one, treat them as the same actor. This is
        # how we catch an attacker rotating session ids / source addresses.
        canonical = event.source
        if event.fingerprint:
            bkey = event.fingerprint
            prior = self.fingerprints.get(bkey)
            if prior and prior != event.source:
                canonical = prior          # inherit the prior actor's state
            else:
                self.fingerprints[bkey] = canonical
        st = self.sources.get(canonical)
        if st is None:
            st = SourceState(canonical, self.window)
            st.behavior_key = event.fingerprint
            self.sources[canonical] = st
        return st

    def _run_detectors(self, ev: Event, st: SourceState) -> List[Finding]:
        out: List[Finding] = []
        for det in (
            self._d_authz_violation,
            self._d_idor,
            self._d_broken_auth,
            self._d_token_anomaly,
            self._d_session_manipulation,
            self._d_bruteforce,
            self._d_enumeration,
            self._d_probing,
            self._d_rate,
        ):
            f = det(ev, st)
            if f:
                out.append(f)
        return out

    # --- individual detectors -------------------------------------------- #
    def _d_authz_violation(self, ev: Event, st: SourceState) -> Optional[Finding]:
        # Reaching a protected endpoint with no authentication at all.
        if ev.protected and not ev.authenticated:
            reached = ev.status and 200 <= ev.status < 300
            return Finding(
                kind="authz-unauthenticated",
                confidence=0.9,
                reason=f"unauthenticated request to protected endpoint {ev.endpoint}",
                recommend=Action.REJECT if reached else Action.CHALLENGE,
                successful=bool(reached),
            )
        return None

    def _d_idor(self, ev: Event, st: SourceState) -> Optional[Finding]:
        # Authenticated as one user but touching another user's object.
        if (ev.protected and ev.authenticated and ev.user_id and ev.owner_id
                and ev.user_id != ev.owner_id):
            reached = ev.status and 200 <= ev.status < 300
            return Finding(
                kind="authz-idor",
                confidence=0.85 if reached else 0.7,
                reason=(f"user {ev.user_id} accessed object owned by "
                        f"{ev.owner_id} at {ev.raw_path or ev.endpoint}"),
                recommend=Action.REJECT if reached else Action.MONITOR,
                successful=bool(reached),
            )
        return None

    def _d_broken_auth(self, ev: Event, st: SourceState) -> Optional[Finding]:
        # Privilege escalation signal: success on an admin/protected route while
        # the claimed identity is a normal user.
        role = ev.extra.get("role")
        needs = ev.extra.get("required_role")
        if needs and role and role != needs and ev.status and 200 <= ev.status < 300:
            return Finding(
                kind="privilege-escalation",
                confidence=0.9,
                reason=f"role '{role}' succeeded on endpoint requiring '{needs}'",
                recommend=Action.INVALIDATE,
                successful=True,
            )
        return None

    def _d_token_anomaly(self, ev: Event, st: SourceState) -> Optional[Finding]:
        if ev.token is None:
            return None
        if ev.token_alg and ev.token_alg.lower() == "none":
            return Finding(
                kind="token-alg-none",
                confidence=0.95,
                reason="token presented with alg=none (signature bypass attempt)",
                recommend=Action.INVALIDATE,
                successful=bool(ev.status and 200 <= ev.status < 300),
            )
        if not ev.token_valid:
            return Finding(
                kind="token-invalid",
                confidence=0.75,
                reason="invalid/forged token signature",
                recommend=Action.CHALLENGE,
                successful=False,
            )
        return None

    def _d_session_manipulation(self, ev: Event, st: SourceState) -> Optional[Finding]:
        # Same session id arriving with a shifting client fingerprint => likely
        # session fixation / hijack.
        if not ev.fingerprint:
            return None
        prev = ev.extra.get("session_bound_fingerprint")
        if prev and prev != ev.fingerprint:
            return Finding(
                kind="session-manipulation",
                confidence=0.8,
                reason="session id reused from a different client fingerprint",
                recommend=Action.INVALIDATE,
                successful=False,
            )
        return None

    def _d_bruteforce(self, ev: Event, st: SourceState) -> Optional[Finding]:
        n = len(st.auth_failures)
        if n >= self.auth_fail_limit:
            return Finding(
                kind="auth-bruteforce",
                confidence=min(0.6 + 0.05 * (n - self.auth_fail_limit), 0.95),
                reason=f"{n} failed auth attempts within {self.window:.0f}s",
                recommend=Action.TEMP_BLOCK,
                successful=False,
            )
        return None

    def _d_enumeration(self, ev: Event, st: SourceState) -> Optional[Finding]:
        # Distinct object ids on the same protected route in a short window.
        if ev.protected and ev.raw_path:
            st.seen_objects.add(ev.raw_path)
        recent_objs = {e.raw_path for e in st.events
                       if e.endpoint == ev.endpoint and e.raw_path}
        if len(recent_objs) >= self.enum_limit:
            return Finding(
                kind="enumeration",
                confidence=0.7,
                reason=(f"{len(recent_objs)} distinct object ids on {ev.endpoint} "
                        f"within window"),
                recommend=Action.RATE_LIMIT,
                successful=False,
            )
        return None

    def _d_probing(self, ev: Event, st: SourceState) -> Optional[Finding]:
        if len(st.distinct_404) >= self.probe_404_limit:
            return Finding(
                kind="endpoint-probing",
                confidence=0.6,
                reason=f"{len(st.distinct_404)} 404s within window (hidden-route probing)",
                recommend=Action.RATE_LIMIT,
                successful=False,
            )
        return None

    def _d_rate(self, ev: Event, st: SourceState) -> Optional[Finding]:
        n = len(st.events)
        if n >= self.rate_limit:
            return Finding(
                kind="request-flood",
                confidence=0.55,
                reason=f"{n} requests within {self.window:.0f}s",
                recommend=Action.RATE_LIMIT,
                successful=False,
            )
        return None

    # --- decision & logging ---------------------------------------------- #
    def _decide(self, ev: Event, st: SourceState, findings: List[Finding]) -> dict:
        if not findings:
            return {"action": Action.ALLOW, "action_label": Action.ALLOW.label,
                    "findings": [], "allowed": True, "incident": None}

        # Accumulate threat score (confidence-weighted, severity-weighted).
        for f in findings:
            st.threat_score += f.confidence * (1 + int(f.recommend) * 0.15)

        top = max(findings, key=lambda f: (f.recommend, f.confidence))
        action = top.recommend

        # --- authorized-tester nuance -----------------------------------
        # Do not block/blocklist authorized testers for mere probing, enum, or
        # rate.  But if a finding shows a probe actually SUCCEEDED in reaching a
        # protected resource, we still stop that specific request — preventing
        # unauthorized ACCESS is the win condition, and applies to everyone.
        is_tester = ev.source in self.authorized_testers or st.behavior_key in self.authorized_testers
        succeeded = any(f.successful for f in findings)
        if is_tester and not succeeded:
            # De-escalate coercive controls to monitoring for authorized testing.
            if action >= Action.TEMP_BLOCK:
                action = Action.MONITOR
            elif action >= Action.CHALLENGE:
                action = Action.MONITOR

        # Escalate if this source has a sustained high threat score even when the
        # single finding is mild (adaptive: repeated low-grade abuse adds up).
        if st.threat_score >= 6.0 and action < Action.RATE_LIMIT:
            action = Action.RATE_LIMIT

        # Apply stateful side effects of the chosen action.
        allowed = action in (Action.ALLOW, Action.MONITOR, Action.RATE_LIMIT)
        if action == Action.TEMP_BLOCK:
            st.blocked_until = ev.ts + self.block_seconds
        elif action == Action.INVALIDATE:
            st.invalidated = True
        elif action == Action.CHALLENGE:
            st.reauth_pending = True

        incident = self._log(ev, st, findings, top, action, succeeded)
        return {
            "action": action,
            "action_label": action.label,
            "findings": [asdict(f) | {"recommend": f.recommend.label} for f in findings],
            "allowed": allowed and not succeeded_blocks(action),
            "incident": incident,
        }

    def _log(self, ev: Event, st: SourceState, findings: List[Finding],
             top: Finding, action: Action, succeeded: bool) -> dict:
        rec = {
            "timestamp": round(ev.ts, 3),
            "source": st.source,                 # canonical (post-correlation)
            "reported_source": ev.source,        # as presented on the wire
            "behavior_key": st.behavior_key or None,
            "endpoint": ev.endpoint,
            "raw_path": ev.raw_path or None,
            "method": ev.method,
            "suspicious_behavior": top.kind,
            "all_findings": [f.kind for f in findings],
            "defensive_action": action.label,
            "reason": top.reason,
            "confidence": round(top.confidence, 2),
            "threat_score": round(st.threat_score, 2),
            "attack_successful": succeeded,      # did the actor reach the resource?
            "outcome": "prevented" if succeeded_blocks(action) else
                       ("allowed-monitored" if action <= Action.MONITOR else "throttled"),
        }
        self.incidents.append(rec)
        if self._sink:
            self._sink(rec)
        return rec


def succeeded_blocks(action: Action) -> bool:
    """Actions that stop the current request from being served."""
    return action in (Action.REJECT, Action.INVALIDATE, Action.TEMP_BLOCK)


# --------------------------------------------------------------------------- #
#  Convenience: JSONL incident sink
# --------------------------------------------------------------------------- #
def jsonl_sink(path: str) -> Callable[[dict], None]:
    def _write(rec: dict) -> None:
        with open(path, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    return _write
