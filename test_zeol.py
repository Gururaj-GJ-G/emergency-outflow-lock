"""
ZEOL v0.2 — scenario replay and lifecycle tests.

Replays the five POC scenarios from zeol_poc_scenarios.csv, flags any
divergence from the v0.1 expected outputs (divergences are intentional
policy improvements and are explained), then exercises the lock
lifecycle: create -> denied release -> permitted release -> audit.
"""

import csv
from pathlib import Path

from zeol_engine import (
    LIBRARY_VERSION, POLICY_VERSION, LockManager, assess,
)

DIV = "-" * 78


def replay_scenarios():
    print(f"ZEOL policy {POLICY_VERSION} / signal library {LIBRARY_VERSION}")
    print(DIV)
    rows = list(csv.DictReader(open(Path(__file__).parent / "zeol_poc_scenarios.csv")))
    for row in rows:
        sigs = [s for s in (row["triggered_signals"] or "").split(",") if s]
        r = assess(row["session_id"], row["checkpoint"], sigs)
        expected = row["action"]
        marker = "==" if r.recommended_action == expected else "!="
        print(f"{row['session_id']}  {row['checkpoint']:<20} signals={sigs or '[]'}")
        print(f"  v0.1 expected: {expected:<24} v0.2 decision: {r.recommended_action} {marker}")
        print(f"  score {r.risk_score} ({r.risk_band})  patterns={r.matched_patterns or '[]'}")
        for line in r.explanation:
            print(f"    - {line}")
        print()


def lifecycle_demo():
    print(DIV)
    print("Lock lifecycle demo")
    print(DIV)
    lm = LockManager()

    r = assess("sess_101", "TRANSACTION_ATTEMPT", ["SIM_01", "GEOVEL_01", "BENEF_01"])
    lock = lm.create(r)
    print(f"Created {lock.lock_type} {lock.lock_id}")
    print(f"  scope: {lock.scope}")
    print(f"  expires: {lock.expires_at}")
    print(f"  permitted release paths: {lock.release_paths}")

    # 1) Customer re-auth must NOT be able to lift an emergency lock
    try:
        lm.release(lock.lock_id, via="CUSTOMER_REAUTH", actor="customer_app")
    except PermissionError as e:
        print(f"  release via CUSTOMER_REAUTH denied (correct): {e}")

    # 2) Verified channel can
    lm.release(lock.lock_id, via="VERIFIED_CHANNEL", actor="fraud_ops_ref_7741",
               evidence_ref="callback_case_20260703_018")
    print(f"  release via VERIFIED_CHANNEL succeeded; state={lm.get(lock.lock_id).state}")

    # 3) Double release must fail
    try:
        lm.release(lock.lock_id, via="VERIFIED_CHANNEL", actor="fraud_ops_ref_7741")
    except ValueError as e:
        print(f"  second release rejected (correct): {e}")

    print("\nAudit trail:")
    for evt in lm.audit_trail(lock.lock_id):
        print(f"  {evt['timestamp']}  {evt['event_type']:<22} actor={evt['actor']}  {evt['detail']}")


def edge_cases():
    print()
    print(DIV)
    print("Edge cases: corroboration policy for FP-prone criticals")
    print(DIV)
    for sigs, label in [
        (["EMU_01"], "EMU_01 alone (possible OEM false positive)"),
        (["EMU_01", "APP_01"], "EMU_01 corroborated by app tampering"),
        (["SIM_01"], "SIM_01 alone (possible legitimate SIM upgrade)"),
        (["ROOT_01"], "ROOT_01 alone (power user)"),
    ]:
        r = assess("sess_edge", "LOGIN", sigs)
        print(f"  {label:<50} -> {r.recommended_action} (score {r.risk_score})")


if __name__ == "__main__":
    replay_scenarios()
    lifecycle_demo()
    edge_cases()
