# defender-bot

Defender Bot is a self-contained, dependency-free authorization-boundary defense engine by Syed Abrar Ali. It ingests normalized HTTP request events, correlates behaviour per source over a sliding time window, and decides a proportionate defensive response from a fixed ladder: allow → monitor → rate-limit → challenge (re-authenticate) → invalidate session → temporary block → reject. Every significant decision is emitted as a structured incident record. The problem it addresses is the gap between "block anything unusual" and "let everything through": the engine aims specifically to prevent unauthorized access to protected resources, so it tolerates probing by authorized testers while still stopping any request that actually reaches data it should not.

## Where it is used

It was written for a defensive-security challenge brief as the decision core of a request-filtering bot. It is transport-agnostic: an application hook (WSGI/ASGI middleware), an access-log tailer or a replay script constructs `Event` objects and calls `Defender.observe()`, then enforces the returned action. In the owner's setup it serves as the reference engine for experimenting with abuse detection on self-hosted web services and for replaying captured request logs deterministically.

## How it works

Everything is in `defender.py`.

### Data model

| Class | Role |
| --- | --- |
| `Event` | One normalized request: `ts` (caller-supplied monotonic seconds, so replays are deterministic), `source` (session id, API key or client fingerprint), `method`, `endpoint` (route template), `raw_path` (concrete path), `status`, `authenticated`, `auth_failed`, `user_id`, `owner_id`, `token`, `token_valid`, `token_alg`, `protected`, `fingerprint`, free-form `extra`. |
| `Action` | `IntEnum` ordered by severity: ALLOW, MONITOR, RATE_LIMIT, CHALLENGE, INVALIDATE, TEMP_BLOCK, REJECT; `.label` gives the kebab-case name. |
| `Finding` | Detector output: `kind`, `confidence` (0–1), `reason`, recommended `Action`, and `successful` (did the probe actually reach the resource?). |
| `SourceState` | Rolling per-actor state: recent events, auth failures and 404s (deques pruned to the window), seen object ids, a decaying `threat_score` (half-life 120 s), `blocked_until`, `reauth_pending`, `invalidated`, and `behavior_key`. |

### Cross-source correlation

`_state_for()` maps a request to a canonical actor. If the event carries a client `fingerprint` already seen under a different `source`, the new source inherits the earlier actor's state. This is how session-id or address rotation by one attacker is still treated as one actor.

### Detectors (run in order for every event)

| Finding kind | Trigger | Recommended action |
| --- | --- | --- |
| `authz-unauthenticated` | protected endpoint, not authenticated | REJECT if the app returned 2xx (access succeeded), else CHALLENGE |
| `authz-idor` | authenticated `user_id` differs from the object's `owner_id` on a protected endpoint | REJECT on 2xx, else MONITOR |
| `privilege-escalation` | `extra.role` differs from `extra.required_role` and the response was 2xx | INVALIDATE |
| `token-alg-none` / `token-invalid` | token with `alg=none`, or a token flagged invalid | INVALIDATE / CHALLENGE |
| `session-manipulation` | same session presented from a different bound fingerprint (`extra.session_bound_fingerprint`) | INVALIDATE |
| `auth-bruteforce` | ≥ `auth_fail_limit` failed logins in the window (confidence grows with the count) | TEMP_BLOCK |
| `enumeration` | ≥ `enum_limit` distinct object paths on one route in the window | RATE_LIMIT |
| `endpoint-probing` | ≥ `probe_404_limit` 404s in the window | RATE_LIMIT |
| `request-flood` | ≥ `rate_limit` requests in the window | RATE_LIMIT |

An active temporary block short-circuits everything with an `active-block` finding.

### Decision (`_decide`)

1. No findings → ALLOW, no incident.
2. Each finding adds `confidence × (1 + 0.15 × severity)` to the actor's threat score.
3. The highest-severity finding (ties broken by confidence) sets the action.
4. Authorized-tester nuance: if the source or its behaviour key is in `authorized_testers` and no finding was `successful`, coercive actions are de-escalated to MONITOR. If a probe succeeded in reaching protected data, it is stopped regardless of who sent it.
5. Adaptive escalation: a sustained threat score ≥ 6 raises anything milder to RATE_LIMIT.
6. Side effects: TEMP_BLOCK sets `blocked_until = ts + block_seconds`; INVALIDATE and CHALLENGE set flags on the state for the caller to act on.
7. An incident record is appended to `incidents`, passed to the optional `incident_sink`, and returned.

The result dict is `{action, action_label, findings, allowed, incident}`; `allowed` is false for REJECT, INVALIDATE and TEMP_BLOCK (`succeeded_blocks()`).

### Incident record fields

`timestamp`, canonical `source` and `reported_source`, `behavior_key`, `endpoint`, `raw_path`, `method`, `suspicious_behavior` (top finding), `all_findings`, `defensive_action`, `reason`, `confidence`, `threat_score`, `attack_successful`, `outcome` (`prevented`, `allowed-monitored` or `throttled`). `jsonl_sink(path)` returns a sink that appends each record as one JSON line.

## Setup

Requirements: Python 3.8 or newer, standard library only.

```bash
git clone https://github.com/USER/defender-bot.git
cd defender-bot
```

Configuration is by constructor arguments to `Defender`:

| Argument | Default | Meaning |
| --- | --- | --- |
| `window` | 60 s | sliding window for counters |
| `rate_limit` | 40 | requests per window before RATE_LIMIT |
| `auth_fail_limit` | 5 | failed logins per window before TEMP_BLOCK |
| `enum_limit` | 12 | distinct object ids per route per window |
| `probe_404_limit` | 8 | 404s per window |
| `block_seconds` | 30 | length of a temporary block |
| `authorized_testers` | empty set | sources or fingerprints allowed to probe |
| `incident_sink` | none | callable receiving each incident dict |

## Usage

```python
from defender import Defender, Event, Action, jsonl_sink

d = Defender(authorized_testers={"pentest-key"}, incident_sink=jsonl_sink("incidents.jsonl"))

# an authenticated user reading someone else's record, and the app let it through
ev = Event(ts=10.0, source="sess-A", method="GET", endpoint="/api/users/{id}",
           raw_path="/api/users/1007", status=200, authenticated=True,
           user_id="u42", owner_id="u1007", protected=True, fingerprint="ua-x")
r = d.observe(ev)
print(r["action_label"], r["allowed"])        # reject False
print(r["incident"]["suspicious_behavior"])   # authz-idor

# brute force: five failed logins in a minute from the same source
for i in range(5):
    r = d.observe(Event(ts=20 + i, source="sess-B", method="POST", endpoint="/login",
                        status=401, auth_failed=True))
print(r["action_label"])                      # temp-block

print(len(d.export_incidents()))
```

Integration pattern: build an `Event` in middleware before the handler runs (status 0), call `observe()`, enforce the action (429 for rate-limit, 401 with step-up for challenge, 403 for reject, log out the session for invalidate), and optionally observe again with the final status so "successful" probes are recorded. For deterministic replay, feed events from a log file with their original timestamps.

## Project structure

```
defender-bot/
└── defender.py     # Event/Action/Finding/SourceState models, Defender engine, jsonl_sink
```

## Limitations and notes

- The engine never calls the clock; the caller must pass consistent `ts` values, or pruning and decay will not behave.
- It is an in-memory, single-process engine. Per-source state is not shared between workers or persisted across restarts.
- Detectors rely on the caller supplying honest fields (`protected`, `owner_id`, `required_role`, `token_alg`, `fingerprint`); the engine does not parse requests or tokens itself.
- The threat score, thresholds and de-escalation rules are heuristics tuned for a demo, not calibrated against production traffic.
- `seen_objects` grows without bound for long-lived sources; the enumeration check itself only uses events inside the window.
- The module docstring refers to a `demo.py`; it is not included in this directory, so use the example above as the runnable reference.
