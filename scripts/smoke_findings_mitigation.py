# -*- coding: utf-8 -*-
"""완화 정본 스모크 — #79. 구조화 mitigation(모듈 + /findings 응답) 검증.

검증:
  ① 모듈: 스코프 6개 id + base(AML.T0051)가 구조화 dict 반환(필수 키 존재)
  ② 모듈: 기법별 summary가 서로 다름(획일적 한 줄 제거 확인)
  ③ 모듈: 미매핑 id는 일반 폴백, 서브 id(.000)는 base 폴백
  ④ HTTP: GET /scans/{id}/findings의 mitigation이 객체(구조화)이고 기법 정본과 일치
전제: backend 컨테이너 실행 중.
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_findings_mitigation.py
"""
import os

import httpx

from app.db import SessionLocal
from app.mitigations import get_mitigation
from app.models import (Attempt, AtlasTechnique, Finding, Objective, Scan,
                        TargetProject, User)

BASE = "http://localhost:8000"
_KEYS = {"summary", "cause", "steps", "verify", "references"}
_SCOPE = ["AML.T0054", "AML.T0051.000", "AML.T0051.001",
          "AML.T0056", "AML.T0053", "AML.T0057", "AML.T0051"]


def _check_module() -> bool:
    """① ~ ③ : 순수 모듈 검증(HTTP·DB 없음)."""
    ok = True
    # ① 필수 키 + steps 비어있지 않음
    for aid in _SCOPE:
        m = get_mitigation(aid)
        if set(m) < _KEYS or not m["steps"]:
            print(f"  ✗ {aid} 구조 불량: keys={set(m)} steps={len(m['steps'])}")
            ok = False
    # ② summary 획일성 제거(서로 다름)
    summaries = [get_mitigation(a)["summary"] for a in _SCOPE]
    if len(set(summaries)) != len(summaries):
        print("  ✗ summary 중복(획일적) 발견:", summaries)
        ok = False
    # ③ 미매핑 → 일반 폴백 / 서브id → base 폴백
    unknown = get_mitigation("AML.T9999")
    if unknown != get_mitigation(None):
        print("  ✗ 미매핑 id가 일반 폴백과 다름")
        ok = False
    if get_mitigation("AML.T0051.777") != get_mitigation("AML.T0051"):
        print("  ✗ 서브 id가 base 폴백으로 안 떨어짐")
        ok = False
    print("모듈 검증:", "PASS" if ok else "FAIL")
    return ok


def _check_http(db) -> bool:
    """④ : finding 체인 구성 후 GET /findings 응답의 mitigation 구조 확인."""
    tag = f"smoke-mit-{os.getpid()}"
    aid = "AML.T0054"
    created_tech = None
    u = User(github_id=tag, github_name=tag)
    db.add(u); db.commit(); db.refresh(u)
    t = TargetProject(user_id=u.user_id, project_name=tag)
    db.add(t); db.commit(); db.refresh(t)
    # objective.atlas_technique_id는 atlas_techniques FK → 없으면 생성(정리 대상).
    if db.get(AtlasTechnique, aid) is None:
        created_tech = AtlasTechnique(id=aid, name="LLM Jailbreak")
        db.add(created_tech); db.commit()
    s = Scan(target_id=t.target_id, status="done")
    db.add(s); db.commit(); db.refresh(s)
    o = Objective(scan_id=s.scan_id, atlas_technique_id=aid, status="breached")
    db.add(o); db.commit(); db.refresh(o)
    a = Attempt(objective_id=o.objective_id, prompt_text="p", response_text="r",
                fitness=1.0, breached=True)
    db.add(a); db.commit(); db.refresh(a)
    f = Finding(attempt_id=a.attempt_id, severity="critical", evidence="{}",
                mitigation=get_mitigation(aid)["summary"])
    db.add(f); db.commit(); db.refresh(f)

    try:
        r = httpx.get(f"{BASE}/scans/{s.scan_id}/findings", timeout=10)
        assert r.status_code == 200, r.text
        rows = r.json()
        row = next(x for x in rows if x["findings_id"] == f.findings_id)
        mit = row["mitigation"]
        ok = (isinstance(mit, dict)
              and _KEYS <= set(mit)
              and isinstance(mit["steps"], list) and mit["steps"]
              and mit["summary"] == get_mitigation(aid)["summary"])
        print("HTTP 응답 mitigation 타입:", type(mit).__name__,
              "| keys:", sorted(mit) if isinstance(mit, dict) else "-")
        print("HTTP 검증:", "PASS" if ok else "FAIL")
        return ok
    finally:
        db.delete(f); db.delete(a); db.delete(o); db.delete(s)
        db.commit()
        if created_tech is not None:
            db.delete(db.get(AtlasTechnique, aid)); db.commit()
        db.delete(t); db.delete(u); db.commit()


def main():
    db = SessionLocal()
    try:
        ok = _check_module()
        ok = _check_http(db) and ok
        print("\nSMOKE findings_mitigation:",
              "PASS ✅ (구조화 완화 정본 + /findings 반영)" if ok else "FAIL ❌")
        return 0 if ok else 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
