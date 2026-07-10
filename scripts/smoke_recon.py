# -*- coding: utf-8 -*-
"""정찰 스모크 — #37. ast+grep 프로파일 추출 + 규칙 매핑 + 스캔 objectives 반영.

대상은 임시로 번들 더미앱(app/api/dummy.py). 실제 표적은 팀원 챗봇 레포로 갈아끼움.
① profile_target: 더미 코드에서 system_prompt·tools·defenses 추출
② profile_to_atlas: 프로파일 → 공격유형(atlas) 규칙 매핑
③ 스캔 실행 시 정찰이 objectives에 반영 + target 정찰필드 채워짐
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_recon.py
"""
import os
import time

import httpx

from app.db import SessionLocal
from app.models import Objective, Scan, ScanEvent, TargetProject, User
from app.recon import attack_types_to_atlas, profile_target, profile_to_atlas

BASE = "http://localhost:8000"
DUMMY = "app/api/dummy.py"   # 컨테이너 cwd=/app 기준. 임시 검증 대상.


def main():
    db = SessionLocal()
    tag = f"smoke-recon-{os.getpid()}"
    u = User(github_id=tag, github_name=tag)
    db.add(u)
    db.commit()
    db.refresh(u)
    # config.source_path = 더미앱 → 워커가 정찰 때 이 코드를 분석
    t = TargetProject(user_id=u.user_id, project_name=tag, config={"source_path": DUMMY})
    db.add(t)
    db.commit()
    db.refresh(t)

    ok1 = ok2 = ok3 = False
    scan_id = None
    try:
        # ① profile_target 직접(더미 코드)
        src = open(DUMMY, encoding="utf-8").read()
        p = profile_target(t, source=src)
        print("① 프로파일:", {"has_sp": p["has_system_prompt"], "tools": p["tools"],
                            "defenses": p["defenses"], "rag": p["rag_sources"],
                            "model": p["model"], "source": p["source"]})
        ok1 = (p["has_system_prompt"] and p["tools"] and "AcmeBank" in p["system_prompt"])

        # ② 매핑 규칙
        atlas = profile_to_atlas(p)
        types = attack_types_to_atlas(["jailbreak", "tool_misuse", "unknown_x"])
        print("② profile→atlas:", atlas, "| attack_types→atlas:", types)
        ok2 = ("AML.T0053" in atlas and "AML.T0056" in atlas
               and "AML.T0051.000" in atlas and "AML.T0054" in atlas
               and types == ["AML.T0054", "AML.T0053"])

        # ③ 스캔 통해 objectives 반영 + target 정찰필드
        r = httpx.post(f"{BASE}/scans",
                       json={"target_id": t.target_id, "config": {"source_path": DUMMY}},
                       timeout=10)
        scan_id = r.json()["scan_id"]
        for _ in range(40):
            g = httpx.get(f"{BASE}/scans/{scan_id}", timeout=10).json()
            if g["status"] in ("done", "failed"):
                break
            time.sleep(0.5)
        db.expire_all()
        objs = db.query(Objective).filter_by(scan_id=scan_id).all()
        atlas_ids = sorted({o.atlas_technique_id for o in objs})
        t2 = db.get(TargetProject, t.target_id)
        print("③ 스캔 status:", g["status"], "| objectives:", atlas_ids,
              "| target.tools:", t2.tools)
        ok3 = (g["status"] == "done" and "AML.T0053" in atlas_ids
               and "AML.T0056" in atlas_ids and (t2.tools or {}).get("detected"))

        print("\nSMOKE recon:", "PASS ✅ (추출+매핑+스캔반영)"
              if (ok1 and ok2 and ok3) else f"FAIL ❌ (ok1={ok1} ok2={ok2} ok3={ok3})")
        return 0 if (ok1 and ok2 and ok3) else 1
    finally:
        if scan_id is not None:
            db.query(ScanEvent).filter_by(scan_id=scan_id).delete()
            db.query(Objective).filter_by(scan_id=scan_id).delete()
            db.commit()
            s = db.get(Scan, scan_id)
            if s is not None:
                db.delete(s)
            db.commit()
        db.delete(t)
        db.delete(u)
        db.commit()
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
