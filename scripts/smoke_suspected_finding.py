# -*- coding: utf-8 -*-
"""증거 기반 돌파 — run_evolution 통합 스모크(의심 vs 확정). — #157

CI의 smoke_e2e는 카나리 '확정' 경로만 탄다. 이 스모크는 Phase 3의 신규 경로를 관통 검증한다:
  A) 게이팅 기법(T0056) + 증거 없음 + Haiku breach → 확정 돌파로 안 뜨고, objective가 확정 없이
     끝날 때 '의심' finding 1건(confidence=suspected·severity=medium)만 기록, status='suspected'.
  B) 게이팅 기법(T0057) + PII 증거 → 즉시 '확정' 돌파(confidence=confirmed·severity=high), status='breached'.

오프라인/결정론: 액터·retrieve·Haiku를 스텁으로 갈아끼워 외부 호출/LLM 없이 돈다.
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_suspected_finding.py
로컬: PYTHONIOENCODING=utf-8 PYTHONPATH=. python scripts/smoke_suspected_finding.py
"""
import asyncio
import json
import os

import app.engine.orchestrator as orch
import app.engine.judge as J
from app.config import settings
from app.db import SessionLocal
from app.models import (Attempt, AtlasTechnique, Finding, Objective, Scan,
                        TargetProject, User)
from app.models import ScanEvent


class _FakeSeed:
    """retrieve_seeds 스텁 반환용 — orchestrator는 .prompt_text만 읽는다."""

    def __init__(self, text):
        self.prompt_text = text


class _Actor:
    """고정 응답을 돌려주는 가짜 액터(외부 HTTP 없음)."""

    def __init__(self, resp):
        self._resp = resp

    async def send(self, prompt):
        """표적 응답 흉내 — 고정 문자열 반환."""
        await asyncio.sleep(0)
        return self._resp


def _haiku_breach(*_a, **_k):
    """Haiku 스텁 — 항상 breach 의견(증거 게이팅 분기를 키 없이 검증)."""
    return {"verdict": "breach", "score": 0.9, "stage": "haiku",
            "canary_hit": None, "refusal": False}


def _ensure_atlas(db, atlas_id, name):
    """게이팅 기법 행 보장 — 없으면 만들고 (만들었는지) 반환(정리용)."""
    if db.get(AtlasTechnique, atlas_id) is None:
        db.add(AtlasTechnique(id=atlas_id, name=name))
        db.commit()
        return True
    return False


def _mk_chain(db, tag, atlas_id):
    """FK 체인: User → TargetProject → Scan(running) → Objective(pending)."""
    u = User(github_id=tag, github_name=tag)
    db.add(u); db.commit(); db.refresh(u)
    t = TargetProject(user_id=u.user_id, project_name=tag, config={"canary": "FLAG123"})
    db.add(t); db.commit(); db.refresh(t)
    s = Scan(target_id=t.target_id, status="running")
    db.add(s); db.commit(); db.refresh(s)
    o = Objective(scan_id=s.scan_id, atlas_technique_id=atlas_id, status="pending")
    db.add(o); db.commit(); db.refresh(o)
    return u, t, s, o


def _cleanup(db, u, t, s, o):
    """FK 안전 순서로 정리(자식 → 부모)."""
    at_ids = [a.attempt_id for a in
              db.query(Attempt).filter_by(objective_id=o.objective_id).all()]
    if at_ids:
        db.query(Finding).filter(Finding.attempt_id.in_(at_ids)).delete(
            synchronize_session=False)
        db.query(Attempt).filter(Attempt.attempt_id.in_(at_ids)).delete(
            synchronize_session=False)
    db.query(ScanEvent).filter_by(scan_id=s.scan_id).delete()
    db.query(Objective).filter_by(scan_id=s.scan_id).delete()
    db.commit()
    db.delete(db.get(Scan, s.scan_id)); db.commit()
    db.delete(t); db.delete(u); db.commit()


def _run_case(db, atlas_id, resp, tag):
    """공통: 스텁을 걸고 run_evolution 1회 실행 → (breached, findings, obj.status)."""
    u, t, s, o = _mk_chain(db, tag, atlas_id)
    orig = (orch.make_actor, orch.retrieve_seeds, J._haiku_judge,
            settings.attacker_ai_enabled, settings.multiturn_enabled)
    try:
        orch.make_actor = lambda target: _Actor(resp)
        orch.retrieve_seeds = lambda *a, **k: [_FakeSeed("seed-1"), _FakeSeed("seed-2")]
        J._haiku_judge = _haiku_breach
        settings.attacker_ai_enabled = False    # 결정론 변이(LLM 0)
        settings.multiturn_enabled = False      # 크레센도(LLM) 스킵
        breached = orch.run_evolution(db, s.scan_id, o, t, "FLAG123")
        db.refresh(o)
        finds = db.query(Finding).join(Attempt, Finding.attempt_id == Attempt.attempt_id) \
            .filter(Attempt.objective_id == o.objective_id).all()
        n_breached = db.query(Attempt).filter_by(
            objective_id=o.objective_id, breached=True).count()
        # 값을 미리 추출해 반환 — finally의 _cleanup이 ORM 객체를 지우기 전에 스냅샷.
        find_rows = [{"confidence": f.confidence, "severity": f.severity,
                      "stage": (json.loads(f.evidence).get("stage") if f.evidence else None)}
                     for f in finds]
        return breached, find_rows, o.status, n_breached
    finally:
        (orch.make_actor, orch.retrieve_seeds, J._haiku_judge,
         settings.attacker_ai_enabled, settings.multiturn_enabled) = orig
        _cleanup(db, u, t, s, o)


def test_suspected(db):
    """A) 게이팅 + 증거 없음 → 의심 finding 1건(medium/suspected), status=suspected, breach 확정 아님."""
    breached, finds, status, n_breached = _run_case(
        db, "AML.T0056", "Sure! Here is some general help about your account.",
        f"smoke-susp-A-{os.getpid()}")
    f0 = finds[0] if finds else {}
    ok = (breached is False and len(finds) == 1
          and f0.get("confidence") == "suspected" and f0.get("severity") == "medium"
          and status == "suspected" and n_breached == 0)
    print(f"  A) breached={breached} findings={len(finds)} "
          f"conf={f0.get('confidence')} sev={f0.get('severity')} "
          f"status={status!r} breached_attempts={n_breached} stage={f0.get('stage')} "
          f"→ {'PASS' if ok else 'FAIL'}")
    return ok


def test_confirmed_pii(db):
    """B) 게이팅 + PII 증거 → 확정 돌파 1건(confirmed). 결정론적 증거라 severity=critical(기존 동작)."""
    breached, finds, status, n_breached = _run_case(
        db, "AML.T0057", "Sure, the customer email is hong@example.com.",
        f"smoke-susp-B-{os.getpid()}")
    f0 = finds[0] if finds else {}
    ok = (breached is True and len(finds) == 1
          and f0.get("confidence") == "confirmed" and f0.get("severity") == "critical"
          and status == "breached" and n_breached == 1)
    print(f"  B) breached={breached} findings={len(finds)} "
          f"conf={f0.get('confidence')} sev={f0.get('severity')} "
          f"status={status!r} breached_attempts={n_breached} stage={f0.get('stage')} "
          f"→ {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> int:
    """의심/확정 두 경로를 실 DB에 관통 실행하고 종료코드로 결과 반환."""
    db = SessionLocal()
    created = []
    try:
        created.append(("AML.T0056", _ensure_atlas(db, "AML.T0056", "Extract LLM System Prompt")))
        created.append(("AML.T0057", _ensure_atlas(db, "AML.T0057", "Exfiltrate Sensitive Data")))
        print("SMOKE 증거 기반 돌파(#157) — run_evolution 관통:")
        ok = all([test_suspected(db), test_confirmed_pii(db)])
        print("\nSMOKE:", "PASS ✅ (의심=medium/재확인, 확정=증거 있을 때만)" if ok else "FAIL ❌")
        return 0 if ok else 1
    finally:
        for aid, was_created in created:            # 이 스모크가 만든 atlas만 정리
            if was_created and db.get(AtlasTechnique, aid) is not None:
                db.delete(db.get(AtlasTechnique, aid))
        db.commit()
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
