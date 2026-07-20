# -*- coding: utf-8 -*-
"""스캔 이력 스모크(#150) — scan-history.

FastAPI TestClient + get_current_user 오버라이드(smoke_projects 패턴). 두 스캔을 직접
시드(objective 판정 상태·attempt fitness·findings 심각도)해 이력 집계를 검증한다.
코드 diff(version-diff)는 폐기돼 이 스크립트에서도 제거했다 — 비교 분석은 프론트가
heatmap·findings로 계산한다(frontend#45).

검증:
  - scan-history: 최신순·commit_sha·총/방어/돌파 집계
  - scan-history 위험도(#144): risk_score·critical_count, 100 상한, /report와 값 일치
  - 소유권: 타인 scan-history 403

실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_scan_history.py
"""
from fastapi.testclient import TestClient

from app.main import app
from app.db import SessionLocal
from app.api.projects import _scan_severity_agg
from app.deps import get_current_user
from app.models import (Attempt, AtlasTechnique, Finding, Objective, Scan,
                        TargetProject, User)

results = []
_GH = ["smoke-vc-owner", "smoke-vc-other"]
_PROJ = "smoke-vc-proj"
# prev → cur 로 설계한 기법별 판정(status: breached | safe | pending).
_TECHS = ["AML.T0056", "AML.T0057", "AML.T0051.000", "AML.T0054", "AML.T0053"]
_PREV = {"AML.T0056": "breached", "AML.T0057": "breached",
         "AML.T0051.000": "safe", "AML.T0054": "safe"}
# T0053: 현재 스캔에서 미확정(pending) — 방어(defended)로 오집계되면 안 된다.
_CUR = {"AML.T0056": "safe", "AML.T0057": "breached",
        "AML.T0051.000": "breached", "AML.T0054": "safe", "AML.T0053": "pending"}
# 스캔별 findings 심각도(#144 위험도·critical 집계용). 기법당 여러 건 가능.
#   prev: critical×2 + high = 40+40+25 = 105 → 100 상한 / critical_count 2
#   cur : high + medium + 빈값(=low 폴백) = 25+10+5 = 40 / critical_count 0
_SEV_PREV = {"AML.T0056": ["critical", "critical"], "AML.T0057": ["high"]}
_SEV_CUR = {"AML.T0057": ["high"], "AML.T0051.000": ["medium", ""]}
_EXP_RISK = {"prev": 100.0, "cur": 40.0}
_EXP_CRIT = {"prev": 2, "cur": 0}


def check(name, cond):
    results.append((name, cond))
    print(f"  {'✅' if cond else '❌'} {name}")


def _seed_scan(db, target_id, sha, status_map, sev_map=None):
    """스캔 1건 + 기법별 objective/attempt 시드. status_map[atlas]=breached|safe.

    sev_map[atlas]=[심각도…]가 있으면 그 기법의 attempt에 findings를 달아
    scan-history의 위험도·critical 집계(#144)를 검증할 수 있게 한다.
    """
    scan = Scan(target_id=target_id, status="done", commit_sha=sha)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    for atlas_id, st in status_map.items():
        obj = Objective(scan_id=scan.scan_id, atlas_technique_id=atlas_id, status=st)
        db.add(obj)
        db.commit()
        db.refresh(obj)
        breached = st == "breached"
        attempt = Attempt(objective_id=obj.objective_id, prompt_text="p",
                          fitness=0.9 if breached else 0.2, breached=breached)
        db.add(attempt)
        db.commit()
        db.refresh(attempt)
        for sev in (sev_map or {}).get(atlas_id, []):
            db.add(Finding(attempt_id=attempt.attempt_id, severity=sev))
    db.commit()
    return scan.scan_id


def setup():
    db = SessionLocal()
    try:
        # 재실행 대비 정리(프로젝트→스캔→objective/attempt).
        _cleanup(db)
        for atlas_id in _TECHS:                       # name 매핑 확인용 atlas 마스터 보장
            if db.get(AtlasTechnique, atlas_id) is None:
                db.add(AtlasTechnique(id=atlas_id, name=f"技法 {atlas_id}"))
        owner = User(github_id=_GH[0], github_name="owner")
        other = User(github_id=_GH[1], github_name="other")
        db.add(owner); db.add(other); db.commit()
        db.refresh(owner); db.refresh(other)
        target = TargetProject(user_id=owner.user_id, project_name=_PROJ,
                               repo_url="http://not-github/r")  # github 아님 → diff 즉시 []
        db.add(target); db.commit(); db.refresh(target)
        prev_id = _seed_scan(db, target.target_id, "baaaaaa1234", _PREV, _SEV_PREV)
        cur_id = _seed_scan(db, target.target_id, "ccccccc5678", _CUR, _SEV_CUR)
        return owner.user_id, other.user_id, target.target_id, prev_id, cur_id
    finally:
        db.close()


def _cleanup(db):
    tids = [t.target_id for t in db.query(TargetProject).filter(
        TargetProject.project_name == _PROJ)]
    if tids:
        sids = [s.scan_id for s in db.query(Scan).filter(Scan.target_id.in_(tids))]
        if sids:
            oids = [o.objective_id for o in db.query(Objective).filter(
                Objective.scan_id.in_(sids))]
            if oids:
                aids = [a.attempt_id for a in db.query(Attempt).filter(
                    Attempt.objective_id.in_(oids))]
                if aids:                      # findings가 attempt를 FK로 잡고 있어 먼저 삭제
                    db.query(Finding).filter(Finding.attempt_id.in_(aids)).delete(
                        synchronize_session=False)
                db.query(Attempt).filter(Attempt.objective_id.in_(oids)).delete(
                    synchronize_session=False)
            db.query(Objective).filter(Objective.scan_id.in_(sids)).delete(
                synchronize_session=False)
        db.query(Scan).filter(Scan.target_id.in_(tids)).delete(synchronize_session=False)
    db.query(TargetProject).filter(TargetProject.project_name == _PROJ).delete(
        synchronize_session=False)
    db.query(User).filter(User.github_id.in_(_GH)).delete(synchronize_session=False)
    db.commit()


def teardown():
    db = SessionLocal()
    try:
        _cleanup(db)
    finally:
        db.close()


def as_user(uid):
    def _fake():
        db = SessionLocal()
        try:
            return db.get(User, uid)
        finally:
            db.close()
    app.dependency_overrides[get_current_user] = _fake


def main():
    owner_id, other_id, tid, prev_id, cur_id = setup()
    client = TestClient(app)
    try:
        as_user(owner_id)

        # --- scan-history ---
        r = client.get(f"/projects/{tid}/scan-history")
        check("scan-history 200", r.status_code == 200)
        body = r.json()
        scans = body.get("scans", [])
        check("scan-history project_name", body.get("project_name") == _PROJ)
        check("scan-history 2건", len(scans) == 2)
        check("scan-history 최신순(cur 먼저)",
              scans and scans[0]["scan_id"] == cur_id and scans[1]["scan_id"] == prev_id)
        cur_row = scans[0]
        check("scan-history commit_sha 노출", cur_row["commit_sha"] == "ccccccc5678")
        # cur: 총5(T0053 pending 포함) · 방어2(T0056,T0054) · 돌파2(T0057,T0051.000).
        # pending은 방어로 세지 않음 → defended==2 (총-돌파=3 아님).
        check("scan-history 집계(총5·방어2·돌파2, pending 방어 제외)",
              cur_row["total_objectives"] == 5 and cur_row["defended"] == 2
              and cur_row["breach_count"] == 2)

        # --- scan-history 위험도·critical 집계(#144, §4 추세용) ---
        prev_row = scans[1]
        check("scan-history risk_score(cur=40 · 빈 severity는 low 폴백)",
              cur_row["risk_score"] == _EXP_RISK["cur"])
        check("scan-history risk_score 100 상한(prev 105→100)",
              prev_row["risk_score"] == _EXP_RISK["prev"])
        check("scan-history critical_count(prev 2 · cur 0)",
              prev_row["critical_count"] == _EXP_CRIT["prev"]
              and cur_row["critical_count"] == _EXP_CRIT["cur"])
        # 공식이 갈라지지 않도록 /report 정본과 교차 검증.
        for row in (cur_row, prev_row):
            rep = client.get(f"/scans/{row['scan_id']}/report").json()
            check(f"#{row['scan_id']} risk_score == /report 값",
                  row["risk_score"] == rep["risk_score"])
            check(f"#{row['scan_id']} critical_count == /report severity_counts",
                  row["critical_count"] == rep["severity_counts"].get("critical", 0))
        # findings 없는 스캔은 집계 dict에 아예 안 잡힘 → 응답에서 0.0/0으로 폴백.
        db = SessionLocal()
        try:
            check("findings 없는 스캔은 집계에서 빠짐(0.0 폴백 경로)",
                  _scan_severity_agg(db, [cur_id, -1]).get(-1) is None
                  and _scan_severity_agg(db, []) == {})
        finally:
            db.close()

        # --- 소유권 ---
        as_user(other_id)
        r = client.get(f"/projects/{tid}/scan-history")
        check("타인 scan-history → 403", r.status_code == 403)
    finally:
        app.dependency_overrides.clear()
        teardown()

    ok = all(c for _, c in results)
    print(f"\nSMOKE scan-history: {'PASS ✅' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
