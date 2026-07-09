# -*- coding: utf-8 -*-
"""비동기 스캔 태스크 (Celery). — ARCHITECTURE.md §5

`POST /scans` 가 `run_scan.delay(scan_id)` 로 Redis 큐에 넣으면, 별 프로세스인
워커가 꺼내 이 함수를 실행한다. 진화 엔진 배선(recon→진화루프→결과)은 다음 이슈(#36).
지금은 **Celery 관통**(큐→워커 수신)만 뼈대로 세운다.
"""
import logging

from .celery_app import celery_app

log = logging.getLogger("redteam.tasks")


@celery_app.task(name="run_scan")
def run_scan(scan_id: int) -> dict:
    """스캔 1건 실행. TODO(#36): recon → objectives별 orchestrator.run_evolution → 결과 저장 + SSE.
    지금은 워커가 큐에서 태스크를 받는지 확인하는 뼈대."""
    log.info("[worker] run_scan 수신: scan_id=%s", scan_id)
    return {"scan_id": scan_id, "status": "received"}
