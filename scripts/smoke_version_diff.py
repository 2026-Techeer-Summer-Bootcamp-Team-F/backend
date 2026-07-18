# -*- coding: utf-8 -*-
"""스캔 버전 관리 스모크(#132) — scan-history + version-diff.

FastAPI TestClient + get_current_user 오버라이드(smoke_projects 패턴). 두 스캔을 직접
시드(objective 판정 상태·attempt fitness)해 기법별 판정 변화를 계산한다. 네트워크 없이
동작(리포지토리를 github가 아닌 URL로 둬 fetch_commit_diff가 즉시 []).

검증:
  - _parse_patch 순수 파싱(context 양쪽·del 좌·add 우·신규파일 before=null)
  - scan-history: 최신순·commit_sha·총/방어/돌파 집계
  - version-diff: solved/open/keep/regressed verdict + 우선순위 정렬
  - baseline(이전 스캔 없음) → results:[] + diff_error
  - GitHub 없는 diff → files:[] + diff_error (raw 500 없음)
  - 소유권: 타인 scan-history 403 / version-diff 404, base 다른표적 400

실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_version_diff.py
"""
from fastapi.testclient import TestClient

from app.main import app
from app.db import SessionLocal
from app.deps import get_current_user
from app.models import (Attempt, AtlasTechnique, Objective, Scan,
                        TargetProject, User)
from app.recon import _parse_patch

results = []
_GH = ["smoke-vc-owner", "smoke-vc-other"]
_PROJ = "smoke-vc-proj"
# prev → cur 로 설계한 기법별 판정(status: breached | safe)과 기대 verdict.
#   T0056: breached→safe = solved / T0057: breached→breached = open
#   T0051.000: safe→breached = regressed / T0054: safe→safe = keep
_TECHS = ["AML.T0056", "AML.T0057", "AML.T0051.000", "AML.T0054"]
_PREV = {"AML.T0056": "breached", "AML.T0057": "breached",
         "AML.T0051.000": "safe", "AML.T0054": "safe"}
_CUR = {"AML.T0056": "safe", "AML.T0057": "breached",
        "AML.T0051.000": "breached", "AML.T0054": "safe"}
_EXPECT = {"AML.T0056": "solved", "AML.T0057": "open",
           "AML.T0051.000": "regressed", "AML.T0054": "keep"}


def check(name, cond):
    results.append((name, cond))
    print(f"  {'✅' if cond else '❌'} {name}")


def _seed_scan(db, target_id, sha, status_map):
    """스캔 1건 + 기법별 objective/attempt 시드. status_map[atlas]=breached|safe."""
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
        db.add(Attempt(objective_id=obj.objective_id, prompt_text="p",
                       fitness=0.9 if breached else 0.2, breached=breached))
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
        prev_id = _seed_scan(db, target.target_id, "baaaaaa1234", _PREV)
        cur_id = _seed_scan(db, target.target_id, "ccccccc5678", _CUR)
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
    # --- 순수 파싱 검증(네트워크 무관) ---
    before, after = _parse_patch("@@ -1,2 +1,2 @@\n ctx\n-old\n+new")
    check("_parse_patch context 양쪽 유지",
          before[0] == {"n": 1, "t": "", "c": "ctx"} and after[0] == {"n": 1, "t": "", "c": "ctx"})
    check("_parse_patch del=좌측만 / add=우측만",
          before[1]["t"] == "del" and before[1]["c"] == "old"
          and after[1]["t"] == "add" and after[1]["c"] == "new")
    b2, a2 = _parse_patch("@@ -0,0 +1,1 @@\n+x")
    check("_parse_patch 신규파일 before=null", b2 is None and a2 and a2[0]["t"] == "add")

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
        check("scan-history 집계(총4·방어2·돌파2)",
              cur_row["total_objectives"] == 4 and cur_row["defended"] == 2
              and cur_row["breach_count"] == 2)

        # --- version-diff (cur, base 자동=prev) ---
        r = client.get(f"/scans/{cur_id}/version-diff")
        check("version-diff 200", r.status_code == 200)
        vd = r.json()
        check("version-diff base 자동=prev", vd.get("base_scan_id") == prev_id)
        check("version-diff baseline False", vd.get("baseline") is False)
        check("version-diff sha 쌍", vd.get("base_sha") == "baaaaaa1234"
              and vd.get("head_sha") == "ccccccc5678")
        verdicts = {x["atlas_technique_id"]: x["verdict"] for x in vd.get("results", [])}
        check("verdict solved/open/keep/regressed 전부 일치", verdicts == _EXPECT)
        # before/after status 확인(한 건)
        solved = next(x for x in vd["results"] if x["atlas_technique_id"] == "AML.T0056")
        check("solved before=breached/after=defended",
              solved["before"]["status"] == "breached" and solved["after"]["status"] == "defended")
        # 정렬 우선순위: solved → regressed → open → keep
        order = [x["verdict"] for x in vd["results"]]
        check("version-diff 정렬(변화 먼저)",
              order == ["solved", "regressed", "open", "keep"])
        # GitHub 없는 diff → files 비고 diff_error
        check("version-diff files 빈배열", vd.get("files") == [])
        check("version-diff diff_error 안내", bool(vd.get("diff_error")))

        # --- version-diff 명시 base == 자동 ---
        r2 = client.get(f"/scans/{cur_id}/version-diff?base={prev_id}")
        check("version-diff 명시 base 동일 결과",
              r2.status_code == 200 and r2.json().get("base_scan_id") == prev_id)

        # --- baseline: prev 스캔(이전 없음) ---
        r = client.get(f"/scans/{prev_id}/version-diff")
        check("version-diff baseline True", r.json().get("baseline") is True)
        check("version-diff baseline results 빈배열", r.json().get("results") == [])
        check("version-diff baseline diff_error", bool(r.json().get("diff_error")))

        # --- 소유권 ---
        as_user(other_id)
        r = client.get(f"/projects/{tid}/scan-history")
        check("타인 scan-history → 403", r.status_code == 403)
        r = client.get(f"/scans/{cur_id}/version-diff")
        check("타인 version-diff → 404", r.status_code == 404)
        r = client.get(f"/scans/{cur_id}/version-diff?base={prev_id}")
        check("없는/타인 scan version-diff → 404", r.status_code == 404)
    finally:
        app.dependency_overrides.clear()
        teardown()

    ok = all(c for _, c in results)
    print(f"\nSMOKE version-diff: {'PASS ✅' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
