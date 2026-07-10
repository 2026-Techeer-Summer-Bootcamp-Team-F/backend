# -*- coding: utf-8 -*-
"""scan_manager 스모크 — #35. persist-then-publish 검증.

① scan_events(DB)에 저장되나  ② Redis 채널로 방송돼 구독자(SSE 흉내)가 받나.
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_scan_manager.py
"""
import json
import os
import threading

from app.db import SessionLocal
from app.engine.scan_manager import channel, publish, _redis
from app.models import Scan, ScanEvent, TargetProject, User


def main():
    db = SessionLocal()
    tag = f"smoke-{os.getpid()}"
    # FK 체인: user → target → scan (scan_events가 scan_id FK라 실제 스캔 필요)
    u = User(github_id=tag, github_name=tag)
    db.add(u)
    db.commit()
    db.refresh(u)
    t = TargetProject(user_id=u.user_id, project_name=tag)
    db.add(t)
    db.commit()
    db.refresh(t)
    s = Scan(target_id=t.target_id, status="running")
    db.add(s)
    db.commit()
    db.refresh(s)
    sid = s.scan_id

    # 구독자 스레드(방송 받는 쪽 = SSE 흉내). subscribed로 "구독 확정"을 게이트 →
    # time.sleep 타이밍에 의존하지 않음(레이스 제거). 자기 pubsub은 자기가 닫음.
    received = []
    subscribed = threading.Event()

    def subscriber():
        ps = _redis.pubsub()
        try:
            ps.subscribe(channel(sid))
            subscribed.set()  # 구독 확정 신호
            for m in ps.listen():
                if m["type"] == "message":
                    received.append(json.loads(m["data"]))
                    break
        finally:
            ps.close()

    try:
        th = threading.Thread(target=subscriber, daemon=True)
        th.start()
        subscribed.wait(timeout=3)  # 구독 확정까지 대기(발행 전 보장)

        # 발행 (persist-then-publish)
        out = publish(sid, "progress", {"generation": 2, "best_score": 0.7}, db=db, objective_id=5)
        th.join(timeout=3)

        # 검증
        rows = db.query(ScanEvent).filter_by(scan_id=sid).all()
        print("① DB 저장:", len(rows), "행, 순번 id =", out.get("id"),
              ", payload =", rows[0].payload if rows else None)
        print("② Redis 수신:", received[0] if received else "(없음)")
        ok = (len(rows) == 1 and out.get("id") is not None
              and received and received[0]["event"] == "progress"
              and received[0]["generation"] == 2 and received[0]["objective_id"] == 5)
        print("\nSMOKE scan_manager:", "PASS ✅ (DB 저장 + Redis 방송 관통)" if ok else "FAIL ❌")
    finally:
        # 정리(예외 나도 항상 실행). FK 순서: 자식 scan_events 먼저 삭제·커밋 → 부모.
        db.query(ScanEvent).filter_by(scan_id=sid).delete()
        db.commit()
        db.delete(s)
        db.delete(t)
        db.delete(u)
        db.commit()
        db.close()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
