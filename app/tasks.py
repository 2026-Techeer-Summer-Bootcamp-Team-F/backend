# -*- coding: utf-8 -*-
"""비동기 스캔 태스크. — ARCHITECTURE.md §5

PoC: FastAPI BackgroundTasks 로 run_scan 실행(Celery 없이).
운영: Celery + Redis 브로커로 승격(worker 컨테이너). 인터페이스는 동일.
"""


def run_scan(scan_id: int):
    """스캔 1건 실행: recon → objectives별 진화루프(orchestrator) → 결과 저장.
    TODO: engine.orchestrator.run_evolution 배선 + SSE 발행."""
    raise NotImplementedError("스캔 태스크 배선")
