# -*- coding: utf-8 -*-
"""스캔 전체 시간 제한 — 우아한 마감(graceful deadline) 회귀 스모크. — #139

검증(강제 종료가 아니라 '진행 중 공격 1건까지만' 완료 후 정상 종료):
  A) run_evolution: deadline을 코앞에 주입 → 진행 중이던 공격 1건은 완료되고, 다음 공격은
     시작하지 않고 반환. objective.status는 pending 유지(→ untested/부분 집계).
  B) run_scan: deadline=0 주입 → 남은 목표를 시작하지 않고 status=done(부분)으로 정상 종료.
     scan.progress에 stopped_reason='deadline' 기록(실패 아님).

오프라인/결정론: 액터·retrieve·judge를 스텁으로 갈아끼워 외부 호출/LLM 없이 돈다.
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_deadline.py
전제: atlas_techniques에 최소 1개 행(ci_seed.py). 없으면 SKIP.
"""
import os
import time

import app.engine.orchestrator as orch
import app.tasks as tasks
from app.db import SessionLocal
from app.models import (Attempt, AtlasTechnique, Finding, Objective, Scan,
                        ScanEvent, TargetProject, User)


class _FakeSeed:
    """retrieve_seeds 스텁 반환용 — orchestrator는 .prompt_text만 읽는다."""

    def __init__(self, text):
        self.prompt_text = text


class _SlowActor:
    """공격 1건(send)이 SLEEP초 걸리는 가짜 액터 — deadline 경계를 결정론적으로 만든다."""

    SLEEP = 0.25

    async def send(self, prompt):
        """표적 응답을 흉내: SLEEP초 뒤 무해한 문자열 반환(breach 아님)."""
        time.sleep(self.SLEEP)
        return "죄송하지만 도와드릴 수 없습니다."


def _fake_judge(*_a, **_k):
    """판정 스텁 — 항상 safe(무돌파). LLM 호출 없이 결정론."""
    return {"verdict": "safe", "score": 0.1, "stage": "rule", "canary_hit": None}


def _mk_chain(db, tag, atlas_id, n_objectives=1):
    """FK 체인 생성: User → TargetProject → Scan(running) → Objective(pending)*n."""
    u = User(github_id=tag, github_name=tag)
    db.add(u)
    db.commit()
    db.refresh(u)
    t = TargetProject(user_id=u.user_id, project_name=tag, config={"canary": "FLAG123"})
    db.add(t)
    db.commit()
    db.refresh(t)
    s = Scan(target_id=t.target_id, status="running", started_at=tasks._now())
    db.add(s)
    db.commit()
    db.refresh(s)
    objs = []
    for _ in range(n_objectives):
        o = Objective(scan_id=s.scan_id, atlas_technique_id=atlas_id, status="pending")
        db.add(o)
        objs.append(o)
    db.commit()
    for o in objs:
        db.refresh(o)
    return u, t, s, objs


def _cleanup(db, u, t, s, objs):
    """FK 안전 순서로 정리(자식 → 부모)."""
    obj_ids = [o.objective_id for o in objs]
    if obj_ids:
        at_ids = [a.attempt_id for a in
                  db.query(Attempt).filter(Attempt.objective_id.in_(obj_ids)).all()]
        if at_ids:
            db.query(Finding).filter(Finding.attempt_id.in_(at_ids)).delete(
                synchronize_session=False)
            db.query(Attempt).filter(Attempt.attempt_id.in_(at_ids)).delete(
                synchronize_session=False)
    db.query(ScanEvent).filter_by(scan_id=s.scan_id).delete()
    db.query(Objective).filter_by(scan_id=s.scan_id).delete()
    db.commit()
    db.delete(db.get(Scan, s.scan_id))
    db.commit()
    db.delete(t)
    db.delete(u)
    db.commit()


def test_evolution_stops_after_current_attack(db, atlas_id):
    """A) deadline을 코앞(now+0.15s)에 두고 씨앗 3개를 준다. 첫 공격(0.25s)은 완료되지만
    그 사이 deadline이 지나 둘째 공격은 시작되지 않아야 한다 → Attempt 정확히 1건.
    objective.status는 pending 유지(safe로 찍히지 않음 → untested)."""
    tag = f"smoke-deadline-A-{os.getpid()}"
    u, t, s, objs = _mk_chain(db, tag, atlas_id, n_objectives=1)
    obj = objs[0]
    orig = (orch.make_actor, orch.retrieve_seeds, orch.judge)
    try:
        orch.make_actor = lambda target: _SlowActor()
        orch.retrieve_seeds = lambda *a, **k: [
            _FakeSeed("seed-1"), _FakeSeed("seed-2"), _FakeSeed("seed-3")]
        orch.judge = _fake_judge

        deadline = time.monotonic() + 0.15   # 첫 공격(0.25s)보다 짧게 → 첫 발사 후 초과
        breached = orch.run_evolution(db, s.scan_id, obj, t, "FLAG123", deadline=deadline)

        n_attempts = db.query(Attempt).filter_by(objective_id=obj.objective_id).count()
        db.refresh(obj)
        ok = (breached is False and n_attempts == 1 and obj.status == "pending")
        print(f"  A) breached={breached} attempts={n_attempts} obj.status={obj.status!r} "
              f"→ {'PASS' if ok else 'FAIL'}")
        print("     (진행 중 공격 1건만 완료·다음 공격 미시작·pending 유지=untested)")
        return ok
    finally:
        orch.make_actor, orch.retrieve_seeds, orch.judge = orig
        _cleanup(db, u, t, s, objs)


def test_evolution_no_attack_when_past_deadline(db, atlas_id):
    """A') deadline이 이미 지난 상태 → 공격을 하나도 시작하지 않고 반환(Attempt 0건)."""
    tag = f"smoke-deadline-A2-{os.getpid()}"
    u, t, s, objs = _mk_chain(db, tag, atlas_id, n_objectives=1)
    obj = objs[0]
    orig = (orch.make_actor, orch.retrieve_seeds, orch.judge)
    try:
        orch.make_actor = lambda target: _SlowActor()
        orch.retrieve_seeds = lambda *a, **k: [_FakeSeed("seed-1"), _FakeSeed("seed-2")]
        orch.judge = _fake_judge

        breached = orch.run_evolution(db, s.scan_id, obj, t, "FLAG123",
                                      deadline=time.monotonic() - 1)
        n_attempts = db.query(Attempt).filter_by(objective_id=obj.objective_id).count()
        db.refresh(obj)
        ok = (breached is False and n_attempts == 0 and obj.status == "pending")
        print(f"  A') breached={breached} attempts={n_attempts} obj.status={obj.status!r} "
              f"→ {'PASS' if ok else 'FAIL'}")
        return ok
    finally:
        orch.make_actor, orch.retrieve_seeds, orch.judge = orig
        _cleanup(db, u, t, s, objs)


def test_scan_partial_finalize(db, atlas_id):
    """B) run_scan에 deadline=0 주입 → 남은 목표 미실행, status=done(부분)으로 정상 종료.
    실패 아님 + progress.stopped_reason='deadline' 기록 + objective는 pending(untested)."""
    tag = f"smoke-deadline-B-{os.getpid()}"
    u, t, s, objs = _mk_chain(db, tag, atlas_id, n_objectives=2)
    # run_scan은 pending에서만 진행 → running으로 만든 상태를 pending으로 되돌린다.
    s.status = "pending"
    db.commit()
    orig_recon = tasks._run_recon
    orig_deadline = tasks.settings.scan_deadline_seconds
    try:
        tasks._run_recon = lambda *a, **k: {}       # 정찰(네트워크) 스킵
        tasks.settings.scan_deadline_seconds = 0    # 즉시 마감 → 첫 목표도 시작 안 함
        tasks.run_scan(s.scan_id)                   # celery 태스크 동기 실행

        db.expire_all()
        s2 = db.get(Scan, s.scan_id)
        prog = s2.progress or {}
        remaining_pending = db.query(Objective).filter_by(
            scan_id=s.scan_id, status="pending").count()
        ok = (s2.status == "done"
              and prog.get("stopped_reason") == "deadline"
              and prog.get("partial") is True
              and remaining_pending == 2)
        print(f"  B) status={s2.status!r} stopped_reason={prog.get('stopped_reason')!r} "
              f"pending_objectives={remaining_pending} → {'PASS' if ok else 'FAIL'}")
        print("     (강제 실패 아님·done(부분)·미실행 목표 untested)")
        return ok
    finally:
        tasks._run_recon = orig_recon
        tasks.settings.scan_deadline_seconds = orig_deadline
        _cleanup(db, u, t, s, objs)


def main():
    db = SessionLocal()
    try:
        atlas = db.query(AtlasTechnique).first()
        if atlas is None:
            print("SMOKE deadline: SKIP (atlas_techniques 비어있음 — ci_seed.py 먼저 실행)")
            return 0
        atlas_id = atlas.id
        print("SMOKE deadline (#139) — 우아한 마감:")
        results = [
            test_evolution_stops_after_current_attack(db, atlas_id),
            test_evolution_no_attack_when_past_deadline(db, atlas_id),
            test_scan_partial_finalize(db, atlas_id),
        ]
        ok = all(results)
        print("\nSMOKE deadline:",
              "PASS ✅ (진행 공격 1건 완료 후 정상 종료·부분 결과·상태=done)"
              if ok else "FAIL ❌")
        return 0 if ok else 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
