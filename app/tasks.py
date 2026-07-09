# -*- coding: utf-8 -*-
"""비동기 스캔 태스크 (Celery). — ARCHITECTURE.md §5 · 계획 §2

`POST /scans` 가 `run_scan.delay(scan_id)` 로 Redis 큐에 넣으면, 별 프로세스인
워커가 꺼내 이 함수를 실행한다. 자체 DB 세션(요청 세션과 분리).

#36(관통 뼈대): status pending→running→done + scan_manager로 시작·완료 이벤트 발행.
목표별 진화(retrieve→select→mutate→fire→judge)는 #39에서 run_evolution 배선.
"""
import logging
from datetime import datetime, timezone

from .celery_app import celery_app
from .db import SessionLocal
from .engine.scan_manager import publish
from .models import Objective, Scan

log = logging.getLogger("redteam.tasks")


def _now():
    return datetime.now(timezone.utc)


@celery_app.task(name="run_scan")
def run_scan(scan_id: int) -> dict:
    """스캔 1건을 워커에서 실행. 상태 전이 + 이벤트 발행으로 처음~끝 관통.

    TODO(#39): objectives 순회에서 run_evolution(db, scan, obj, target) 배선.
    지금은 목표를 곧장 done 처리해 파이프 전체를 뚫는다(빈 껍데기 관통).
    """
    log.info("[worker] run_scan 수신: scan_id=%s", scan_id)
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.warning("[worker] scan 없음: scan_id=%s", scan_id)
            return {"scan_id": scan_id, "status": "missing"}

        # ── running ──
        scan.status = "running"
        scan.started_at = _now()
        db.commit()
        publish(scan_id, "log", {"message": "스캔 시작"}, db=db)

        objectives = db.query(Objective).filter_by(scan_id=scan_id).all()
        publish(scan_id, "progress",
                {"phase": "start", "objectives": len(objectives)}, db=db)

        breached = 0
        for obj in objectives:
            # TODO(#39): breached = run_evolution(db, scan, obj, target)
            obj.status = "done"
            db.commit()
            publish(scan_id, "progress", {"phase": "objective_done"},
                    db=db, objective_id=obj.objective_id)

        # ── done ──
        scan.status = "done"
        scan.finished_at = _now()
        db.commit()
        publish(scan_id, "done",
                {"status": "done", "objectives": len(objectives), "breached": breached}, db=db)
        log.info("[worker] run_scan 완료: scan_id=%s (objectives=%s)", scan_id, len(objectives))
        return {"scan_id": scan_id, "status": "done"}

    except Exception:
        # 실패해도 상태를 failed로 남기고 이벤트 발행(사용자에게 보임).
        log.exception("[worker] run_scan 실패: scan_id=%s", scan_id)
        try:
            db.rollback()          # commit 실패 시 세션이 롤백대기 → 재사용 전 정리(안 하면 PendingRollbackError)
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.finished_at = _now()
                db.commit()
                publish(scan_id, "done", {"status": "failed"}, db=db)
        except Exception:
            log.exception("[worker] 실패 상태 기록도 실패: scan_id=%s", scan_id)
        return {"scan_id": scan_id, "status": "failed"}
    finally:
        db.close()
