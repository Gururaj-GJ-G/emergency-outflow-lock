"""
Emergency Outflow Lock (EOL) — Risk Decision Engine
Version 0.2.0

Changes from v0.1:
  1. Versioned signal library loaded from zeol_signals.json. Every assessment
     records library_version + policy_version, so a weight change never
     silently alters decisions on a bank's traffic.
  2. Named combination patterns. Known attack shapes (remote-access takeover,
     SIM-swap ATO, trojan session) are matched as patterns, not just summed.
     Pattern matches produce the strongest explanation a bank reviewer can
     act on: "matched PAT-ATO-2" beats a list of "+25, +25, +15".
  3. Corroboration rules for high-false-positive criticals. TROJAN_01 and
     MAL_01 remain standalone fail-closed. EMU_01 and SIM_01 require one
     corroborating signal to force CRITICAL; alone they produce SOFT_LOCK +
     step-up, because emulator detection and SIM-change flags are the two
     signals most likely to fire on legitimate users.
  4. Lock lifecycle. Locks are stateful objects with TTL, permitted release
     paths, escalation, expiry, and an append-only audit trail. This is the
     part a bank actually consumes: WHO can lift a lock, AFTER what
     re-authentication, WITH what evidence.
  5. Timezone-aware timestamps (datetime.utcnow() removed).

Design principles retained from v0.1:
  - Deterministic, explainable. No black-box ML at this stage.
  - Zero customer PII. Signal IDs and opaque session references only.
  - Fail-closed on confirmed-malware criticals.
  - Every decision emits a structured, auditable evidence payload.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
import json
import uuid

POLICY_VERSION = "0.2.0"

# ---------------------------------------------------------------------------
# Signal library (versioned, loaded from data — never hard-coded)
# ---------------------------------------------------------------------------

_LIB_PATH = Path(__file__).parent / "zeol_signals.json"
_LIB = json.loads(_LIB_PATH.read_text())

LIBRARY_VERSION: str = _LIB["library_version"]
SIGNALS: Dict[str, dict] = _LIB["signals"]
SIGNAL_WEIGHTS: Dict[str, int] = {k: v["weight"] for k, v in SIGNALS.items()}

# ---------------------------------------------------------------------------
# Actions, bands, lock scopes
# ---------------------------------------------------------------------------

class Action(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    SOFT_LOCK = "SOFT_LOCK"
    EMERGENCY_OUTFLOW_LOCK = "EMERGENCY_OUTFLOW_LOCK"

_ACTION_RANK = {a: i for i, a in enumerate(
    [Action.ALLOW, Action.STEP_UP, Action.SOFT_LOCK, Action.EMERGENCY_OUTFLOW_LOCK])}

RISK_BANDS = [
    (0, 30, "LOW", Action.ALLOW),
    (31, 60, "MEDIUM", Action.STEP_UP),
    (61, 85, "HIGH", Action.SOFT_LOCK),
    (86, 100, "CRITICAL", Action.EMERGENCY_OUTFLOW_LOCK),
]

SOFT_LOCK_SCOPE = ["UPI_SEND", "CARD_NOT_PRESENT", "IMPS_OUT"]
FULL_LOCK_SCOPE = ["UPI_SEND", "CARD_NOT_PRESENT", "IMPS_OUT", "NEFT_OUT",
                   "RTGS_OUT", "INTERNATIONAL_CARD", "ATM_WITHDRAWAL", "WALLET_SPEND"]
ALWAYS_ALLOW = ["SALARY_CREDIT", "REFUND", "INCOMING_UPI",
                "INTEREST_CREDIT", "ACCOUNT_DEPOSIT"]

# ---------------------------------------------------------------------------
# Critical overrides — split by evidence quality
# ---------------------------------------------------------------------------
# Standalone: signature-confirmed malware. False-positive rate is low enough
#             to fail closed on a single signal.
# Corroborated: strong but FP-prone signals (emulator heuristics misfire on
#             OEM builds; SIM-change flags fire on legitimate SIM upgrades).
#             They force CRITICAL only alongside >=1 other triggered signal;
#             alone they yield SOFT_LOCK with mandatory step-up.

CRITICAL_STANDALONE = {"TROJAN_01", "MAL_01"}
CRITICAL_CORROBORATED = {"EMU_01", "SIM_01"}

# ---------------------------------------------------------------------------
# Named combination patterns
# ---------------------------------------------------------------------------
# A pattern is a set of signals that, seen together, identify a known attack
# shape with far higher confidence than their additive sum implies. Patterns
# are evaluated on subset match; the most severe resulting action wins.

@dataclass(frozen=True)
class Pattern:
    pattern_id: str
    name: str
    required: frozenset
    action: Action
    rationale: str

PATTERNS: List[Pattern] = [
    Pattern(
        "PAT-ATO-1", "Remote-access session",
        frozenset({"RC_01", "OVER_01"}),
        Action.SOFT_LOCK,
        "Remote-control app plus overlay/accessibility abuse indicates a "
        "screen-sharing scam or RAT session in progress.",
    ),
    Pattern(
        "PAT-ATO-2", "Remote-access takeover with OTP interception",
        frozenset({"RC_01", "OVER_01", "NOTIF_01"}),
        Action.EMERGENCY_OUTFLOW_LOCK,
        "Full remote-access triad: control channel, overlay capture, and "
        "notification listener able to read OTPs. This is the dominant "
        "Android banking-fraud kill chain observed in India; the attacker "
        "can complete transactions without further victim interaction.",
    ),
    Pattern(
        "PAT-ATO-3", "SIM-swap account takeover",
        frozenset({"SIM_01", "GEOVEL_01"}),
        Action.EMERGENCY_OUTFLOW_LOCK,
        "SIM-change indicator combined with impossible-travel anomaly. "
        "Together these corroborate identity compromise rather than a "
        "legitimate SIM upgrade.",
    ),
    Pattern(
        "PAT-TRJ-1", "Trojan-driven phishing session",
        frozenset({"PHISH_01", "TROJAN_01"}),
        Action.EMERGENCY_OUTFLOW_LOCK,
        "Verified phishing click followed by trojan signature match: the "
        "infection vector and the payload observed in the same session.",
    ),
    Pattern(
        "PAT-OTP-1", "OTP exfiltration chain",
        frozenset({"OTPFWD_01", "NOTIF_01"}),
        Action.SOFT_LOCK,
        "OTP auto-forward behaviour with a live notification listener; the "
        "second factor can no longer be trusted for this session.",
    ),
    Pattern(
        "PAT-MULE-1", "Coached first-time transfer",
        frozenset({"BENEF_01", "AMT_01", "GEOVEL_01"}),
        Action.SOFT_LOCK,
        "New high-risk beneficiary, amount far from baseline, and location "
        "anomaly in one attempt — consistent with a coached/social-"
        "engineered transfer even on a clean device.",
    ),
]

# ---------------------------------------------------------------------------
# Lock lifecycle
# ---------------------------------------------------------------------------

class LockState(str, Enum):
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"
    ESCALATED = "ESCALATED"

class ReleasePath(str, Enum):
    CUSTOMER_REAUTH = "CUSTOMER_REAUTH"          # in-app strong re-auth
    VERIFIED_CHANNEL = "VERIFIED_CHANNEL"        # call-back / video KYC
    BRANCH_VERIFICATION = "BRANCH_VERIFICATION"  # in-person
    FRAUD_OPS_OVERRIDE = "FRAUD_OPS_OVERRIDE"    # bank analyst, dual control

# Policy: which release paths may lift which lock type, and default TTLs.
LOCK_POLICY = {
    Action.SOFT_LOCK: {
        "ttl": timedelta(minutes=30),
        "release_paths": {ReleasePath.CUSTOMER_REAUTH,
                          ReleasePath.VERIFIED_CHANNEL,
                          ReleasePath.FRAUD_OPS_OVERRIDE},
        "on_expiry": "RELEASE",   # soft locks self-release if nothing worsens
    },
    Action.EMERGENCY_OUTFLOW_LOCK: {
        "ttl": timedelta(hours=24),
        "release_paths": {ReleasePath.VERIFIED_CHANNEL,
                          ReleasePath.BRANCH_VERIFICATION,
                          ReleasePath.FRAUD_OPS_OVERRIDE},
        "on_expiry": "ESCALATE",  # hard locks never silently open
    },
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


@dataclass
class AuditEvent:
    event_id: str
    lock_id: str
    timestamp: str
    event_type: str          # LOCK_CREATED / RELEASE_ATTEMPT / RELEASED / ...
    actor: str               # SYSTEM / CUSTOMER / FRAUD_OPS / <bank actor ref>
    detail: dict


@dataclass
class Lock:
    lock_id: str
    session_id: str
    assessment_id: str
    lock_type: str                    # SOFT_LOCK | EMERGENCY_OUTFLOW_LOCK
    scope: List[str]
    state: str
    created_at: str
    expires_at: str
    release_paths: List[str]
    released_at: Optional[str] = None
    released_via: Optional[str] = None


class LockManager:
    """In-memory lock store for the POC. In production this is a durable
    store owned by the bank; ZEOL defines the state machine and audit
    contract, not the persistence."""

    def __init__(self) -> None:
        self._locks: Dict[str, Lock] = {}
        self._audit: List[AuditEvent] = []

    # -- internals ----------------------------------------------------------

    def _log(self, lock_id: str, event_type: str, actor: str, detail: dict) -> None:
        self._audit.append(AuditEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            lock_id=lock_id, timestamp=_iso(_now()),
            event_type=event_type, actor=actor, detail=detail))

    def _sweep(self, lock: Lock) -> None:
        """Apply expiry policy lazily on access."""
        if lock.state != LockState.ACTIVE.value:
            return
        if _now() < datetime.fromisoformat(lock.expires_at.replace("Z", "+00:00")):
            return
        policy = LOCK_POLICY[Action(lock.lock_type)]
        if policy["on_expiry"] == "RELEASE":
            lock.state = LockState.EXPIRED.value
            self._log(lock.lock_id, "LOCK_EXPIRED_RELEASED", "SYSTEM",
                      {"reason": "TTL elapsed with no escalating signals"})
        else:
            lock.state = LockState.ESCALATED.value
            self._log(lock.lock_id, "LOCK_ESCALATED", "SYSTEM",
                      {"reason": "Emergency lock TTL elapsed without verified "
                                 "release; case must move to fraud operations"})

    # -- API ----------------------------------------------------------------

    def create(self, assessment: "RiskAssessment") -> Optional[Lock]:
        action = Action(assessment.recommended_action)
        if action not in LOCK_POLICY:
            return None
        policy = LOCK_POLICY[action]
        now = _now()
        lock = Lock(
            lock_id=f"lock_{uuid.uuid4().hex[:12]}",
            session_id=assessment.session_id,
            assessment_id=assessment.assessment_id,
            lock_type=action.value,
            scope=list(assessment.lock_scope),
            state=LockState.ACTIVE.value,
            created_at=_iso(now),
            expires_at=_iso(now + policy["ttl"]),
            release_paths=sorted(p.value for p in policy["release_paths"]),
        )
        self._locks[lock.lock_id] = lock
        self._log(lock.lock_id, "LOCK_CREATED", "SYSTEM", {
            "assessment_id": assessment.assessment_id,
            "risk_band": assessment.risk_band,
            "matched_patterns": assessment.matched_patterns,
            "scope": lock.scope,
        })
        return lock

    def get(self, lock_id: str) -> Optional[Lock]:
        lock = self._locks.get(lock_id)
        if lock:
            self._sweep(lock)
        return lock

    def for_session(self, session_id: str) -> List[Lock]:
        out = [l for l in self._locks.values() if l.session_id == session_id]
        for l in out:
            self._sweep(l)
        return out

    def release(self, lock_id: str, via: str, actor: str,
                evidence_ref: Optional[str] = None) -> Lock:
        lock = self.get(lock_id)
        if lock is None:
            raise KeyError(f"Unknown lock_id: {lock_id}")
        if lock.state != LockState.ACTIVE.value:
            raise ValueError(f"Lock {lock_id} is {lock.state}, not ACTIVE")
        try:
            path = ReleasePath(via)
        except ValueError:
            raise ValueError(f"Unknown release path: {via}")
        if path.value not in lock.release_paths:
            self._log(lock_id, "RELEASE_DENIED", actor, {
                "attempted_path": path.value,
                "permitted_paths": lock.release_paths})
            raise PermissionError(
                f"{path.value} may not release a {lock.lock_type}; "
                f"permitted: {lock.release_paths}")
        lock.state = LockState.RELEASED.value
        lock.released_at = _iso(_now())
        lock.released_via = path.value
        self._log(lock_id, "LOCK_RELEASED", actor, {
            "via": path.value, "evidence_ref": evidence_ref})
        return lock

    def audit_trail(self, lock_id: Optional[str] = None) -> List[dict]:
        events = self._audit if lock_id is None else [
            e for e in self._audit if e.lock_id == lock_id]
        return [asdict(e) for e in events]


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    assessment_id: str
    session_id: str
    checkpoint: str
    timestamp: str
    library_version: str
    policy_version: str
    triggered_signals: List[str]
    raw_score: int
    risk_score: int
    risk_band: str
    recommended_action: str
    matched_patterns: List[str]
    lock_scope: List[str]
    allow_scope: List[str]
    explanation: List[str]


def score_signals(triggered: List[str]) -> int:
    total = 0
    for sig in triggered:
        meta = SIGNALS.get(sig)
        if meta is None:
            continue
        total += min(meta["weight"], meta.get("cap", meta["weight"]))
    return min(total, 100)


def match_patterns(triggered: List[str]) -> List[Pattern]:
    tset = set(triggered)
    return [p for p in PATTERNS if p.required <= tset]


def _band_for(score: int) -> tuple:
    for lo, hi, band, action in RISK_BANDS:
        if lo <= score <= hi:
            return band, action
    return "CRITICAL", Action.EMERGENCY_OUTFLOW_LOCK


def assess(session_id: str, checkpoint: str,
           triggered_signals: List[str]) -> RiskAssessment:
    triggered = list(dict.fromkeys(triggered_signals))  # de-dup, keep order
    raw = score_signals(triggered)
    explanation: List[str] = []

    # 1) Base band from additive score
    band, action = _band_for(raw)
    final_score = raw
    for s in triggered:
        w = SIGNAL_WEIGHTS.get(s, 0)
        explanation.append(f"{s} — {SIGNALS.get(s, {}).get('name', 'unknown')} (+{w})")

    # 2) Pattern escalation (most severe wins)
    matched = match_patterns(triggered)
    for p in matched:
        if _ACTION_RANK[p.action] > _ACTION_RANK[action]:
            action = p.action
        explanation.append(f"Pattern {p.pattern_id} matched: {p.name}. {p.rationale}")

    # 3) Critical overrides
    tset = set(triggered)
    standalone = tset & CRITICAL_STANDALONE
    corroborated = tset & CRITICAL_CORROBORATED
    if standalone:
        action = Action.EMERGENCY_OUTFLOW_LOCK
        explanation.append(
            f"Fail-closed override: {sorted(standalone)} are signature-"
            f"confirmed criticals and cannot be offset by other factors.")
    elif corroborated:
        if len(tset) >= 2:
            action = Action.EMERGENCY_OUTFLOW_LOCK
            explanation.append(
                f"Corroborated critical: {sorted(corroborated)} confirmed by "
                f"additional signals in the same session.")
        elif _ACTION_RANK[action] < _ACTION_RANK[Action.SOFT_LOCK]:
            action = Action.SOFT_LOCK
            explanation.append(
                f"{sorted(corroborated)} triggered without corroboration. "
                f"These signals carry known false-positive risk (emulator "
                f"heuristics, legitimate SIM upgrades), so the response is a "
                f"reversible soft lock with mandatory step-up rather than a "
                f"fail-closed emergency lock.")

    # 4) Align reported score/band with the final action
    if action == Action.EMERGENCY_OUTFLOW_LOCK and final_score < 86:
        final_score = 86
    elif action == Action.SOFT_LOCK and final_score < 61:
        final_score = 61
    band, _ = _band_for(final_score)

    lock_scope: List[str] = (
        FULL_LOCK_SCOPE if action == Action.EMERGENCY_OUTFLOW_LOCK
        else SOFT_LOCK_SCOPE if action == Action.SOFT_LOCK
        else [])

    return RiskAssessment(
        assessment_id=f"zeol_{uuid.uuid4().hex[:12]}",
        session_id=session_id,
        checkpoint=checkpoint,
        timestamp=_iso(_now()),
        library_version=LIBRARY_VERSION,
        policy_version=POLICY_VERSION,
        triggered_signals=triggered,
        raw_score=raw,
        risk_score=final_score,
        risk_band=band,
        recommended_action=action.value,
        matched_patterns=[p.pattern_id for p in matched],
        lock_scope=lock_scope,
        allow_scope=list(ALWAYS_ALLOW),
        explanation=explanation,
    )
