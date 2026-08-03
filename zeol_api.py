"""
Emergency Outflow Lock — FastAPI service layer, v0.2.0

Changes from v0.1:
  - API-key authentication (X-ZEOL-API-Key header; keys from env at POC
    stage, an HSM-backed secret store in production).
  - Idempotency-Key support on /v1/assess so bank-side retries never
    produce two assessments (and never two locks) for one attempt.
  - Lock lifecycle endpoints: fetch, list by session, release with an
    explicit release path, and per-lock audit trail.
  - Version metadata (library + policy) on every response.

Run:  uvicorn zeol_api:app --port 8000
Auth: export ZEOL_API_KEYS="demo-key-1,demo-key-2"   (defaults to zeol-poc-key)
"""

import os
import time
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from zeol_engine import (
    LIBRARY_VERSION, POLICY_VERSION, PATTERNS, SIGNALS,
    CRITICAL_STANDALONE, CRITICAL_CORROBORATED,
    LockManager, assess,
)

app = FastAPI(
    title="Emergency Outflow Lock Decision Service",
    version="0.2.0",
)

locks = LockManager()
_idempotency_cache: Dict[str, dict] = {}

_API_KEYS = {k.strip() for k in
             os.environ.get("ZEOL_API_KEYS", "zeol-poc-key").split(",") if k.strip()}


def require_key(x_zeol_api_key: Optional[str] = Header(default=None)) -> str:
    if x_zeol_api_key not in _API_KEYS:
        raise HTTPException(status_code=401, detail="Missing or invalid API key")
    return x_zeol_api_key


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AssessRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    checkpoint: str = Field(..., description="LOGIN | TRANSACTION_ATTEMPT | KYC | ...")
    triggered_signals: List[str] = Field(default_factory=list)
    bank_ref_id: Optional[str] = Field(
        default=None, description="Bank-side correlation ID. No PII.")


class ReleaseRequest(BaseModel):
    via: str = Field(..., description="CUSTOMER_REAUTH | VERIFIED_CHANNEL | "
                                      "BRANCH_VERIFICATION | FRAUD_OPS_OVERRIDE")
    actor: str = Field(..., description="Opaque actor reference (no PII)")
    evidence_ref: Optional[str] = Field(
        default=None, description="Bank-side reference to re-auth/verification evidence")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/v1/assess")
def run_assessment(req: AssessRequest,
                   _key: str = Depends(require_key),
                   idempotency_key: Optional[str] = Header(default=None)):
    if idempotency_key and idempotency_key in _idempotency_cache:
        return _idempotency_cache[idempotency_key]

    unknown = [s for s in req.triggered_signals if s not in SIGNALS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown signal IDs: {unknown}")

    start = time.perf_counter()
    result = assess(req.session_id, req.checkpoint, req.triggered_signals)
    lock = locks.create(result)

    body = {
        **result.__dict__,
        "bank_ref_id": req.bank_ref_id,
        "lock": lock.__dict__ if lock else None,
        "latency_ms": round((time.perf_counter() - start) * 1000, 2),
    }
    if idempotency_key:
        _idempotency_cache[idempotency_key] = body
    return body


@app.get("/v1/locks/{lock_id}")
def get_lock(lock_id: str, _key: str = Depends(require_key)):
    lock = locks.get(lock_id)
    if lock is None:
        raise HTTPException(status_code=404, detail="Unknown lock_id")
    return lock.__dict__


@app.get("/v1/sessions/{session_id}/locks")
def session_locks(session_id: str, _key: str = Depends(require_key)):
    return {"session_id": session_id,
            "locks": [l.__dict__ for l in locks.for_session(session_id)]}


@app.post("/v1/locks/{lock_id}/release")
def release_lock(lock_id: str, req: ReleaseRequest,
                 _key: str = Depends(require_key)):
    try:
        lock = locks.release(lock_id, via=req.via, actor=req.actor,
                             evidence_ref=req.evidence_ref)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown lock_id")
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return lock.__dict__


@app.get("/v1/locks/{lock_id}/audit")
def lock_audit(lock_id: str, _key: str = Depends(require_key)):
    if locks.get(lock_id) is None:
        raise HTTPException(status_code=404, detail="Unknown lock_id")
    return {"lock_id": lock_id, "events": locks.audit_trail(lock_id)}


@app.get("/v1/signals")
def list_signals(_key: str = Depends(require_key)):
    return {
        "library_version": LIBRARY_VERSION,
        "total_signals": len(SIGNALS),
        "critical_standalone": sorted(CRITICAL_STANDALONE),
        "critical_corroborated": sorted(CRITICAL_CORROBORATED),
        "signals": SIGNALS,
    }


@app.get("/v1/patterns")
def list_patterns(_key: str = Depends(require_key)):
    return {
        "policy_version": POLICY_VERSION,
        "patterns": [{
            "pattern_id": p.pattern_id,
            "name": p.name,
            "required_signals": sorted(p.required),
            "action": p.action.value,
            "rationale": p.rationale,
        } for p in PATTERNS],
    }


@app.get("/v1/health")
def health():
    return {"status": "ok", "service": "zeol-decision-service",
            "policy_version": POLICY_VERSION, "library_version": LIBRARY_VERSION}
