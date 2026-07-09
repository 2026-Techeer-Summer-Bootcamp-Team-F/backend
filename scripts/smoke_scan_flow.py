# -*- coding: utf-8 -*-
"""스캔 전체 흐름 스모크 — #36. POST /scans → 워커 → done 관통.

검증: ① POST /scans가 pending 반환  ② 워커가 status pending→running→done 전이
③ scan_events에 시작(log)·완료(done) 이벤트 기록.
전제: backend·worker 컨테이너 실행 중(워커는 최신 tasks.py 반영 위해 restart 필요).
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_scan_flow.py
"""
import os
import time

import httpx

from app.db import SessionLocal
from app.models import Objective, Scan, ScanEvent, TargetProject, User

BASE = "http://localhost:8000"


def main():
    db = SessionLocal()
    tag = f"smoke-flow-{os.getpid()}"
    # 표적 FK 체인(user → target). 스캔은 API가 만든다.
    u = User(github_id=tag, github_login=tag)
    db.add(u)
    db.commit()
    db.refresh(u)
    t = TargetProject(user_id=u.user_id, project_name=tag)
    db.add(t)
    db.commit()
    db.refresh(t)

    scan_id = None
    try:
        # ① POST /scans
        r = httpx.post(f"{BASE}/scans",
                       json={"target_id": t.target_id, "config": {"attack_types": []}},
                       timeout=10)
        print("① POST /scans:", r.status_code, r.json())
        assert r.status_code == 202, r.text
        scan_id = r.json()["scan_id"]
        assert r.json()["status"] == "pending"

        # ② 워커가 done까지 (최대 ~20초 폴링)
        final = None
        for _ in range(40):
            g = httpx.get(f"{BASE}/scans/{scan_id}", timeout=10).json()
            final = g["status"]
            if final in ("done", "failed"):
                break
            time.sleep(0.5)
        print("② 최종 status:", final)

        # ③ scan_events 기록 확인(자체 세션으로 재조회)
        db.expire_all()
        evs = db.query(ScanEvent).filter_by(scan_id=scan_id).order_by(ScanEvent.scan_events_id).all()
        types = [e.payload.get("event") for e in evs]
        print("③ scan_events:", types)

        ok = (final == "done" and "log" in types and "done" in types)
        print("\nSMOKE scan_flow:", "PASS ✅ (POST→워커→done 관통)" if ok else "FAIL ❌")
        return 0 if ok else 1
    finally:
        # 정리(FK 순서: 자식부터). 스캔이 만들어졌으면 objectives·events 먼저.
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
