# -*- coding: utf-8 -*-
"""Celery 앱 — 진화 스캔을 백그라운드 워커에서 실행. — ARCHITECTURE.md §3.4

FastAPI(웹, 빠른 응답)와 워커(무거운 스캔)는 별 프로세스. 둘을 잇는 브로커(태스크 배달)는
RabbitMQ, 결과저장(result backend)은 Redis (2026-07-10 브로커 분리 결정).
`POST /scans`가 `run_scan.delay(id)`로 큐에 넣으면 워커가 꺼내 실행.
※ 실시간 진행(SSE)은 Redis pub/sub이 아니라 scan_events(DB) 폴링으로 흐른다(scan_manager).

실행:
  워커  = celery -A app.celery_app worker --loglevel=info   (docker compose worker 서비스)
  큐잉  = from app.tasks import run_scan; run_scan.delay(scan_id)
"""
from celery import Celery
from celery.signals import worker_process_init

from .config import settings

celery_app = Celery(
    "redteam",
    broker=settings.rabbitmq_url,       # 큐(일감 배달)  — RabbitMQ (정식 브로커, 유실 완화)
    backend=settings.redis_url,         # 결과 저장       — Redis (result backend)
    include=["app.tasks"],              # 태스크 모듈 등록(run_scan)
)

celery_app.conf.update(
    # 유실 방어(계획 §8-A): 워커가 태스크 완료해야 ack → 중간에 죽으면 재큐잉
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # 스캔 1건 시간제한(계획 §8 · #139): 주 경로는 앱 레벨 우아한 마감(SCAN_DEADLINE_SECONDS,
    # 기본 600s) — 초과 시 진행 중 공격 1건만 마치고 정상 종료(부분 결과). 아래 Celery 값은
    # 그 위의 백스톱이며 deadline에서 파생한다: soft(+180=780s) 도달 시 run_scan이
    # SoftTimeLimitExceeded를 잡아 동일한 우아 마감으로 흐른다(failed 아님·ack·재전달 없음).
    # hard(+240=840s)는 soft마저 못 먹힌 경우의 최종 강제 kill.
    # 순서: 600(app deadline) < 정상 마감 ~710 < 780(soft) < 840(hard).
    task_soft_time_limit=settings.scan_deadline_seconds + 180,
    task_time_limit=settings.scan_deadline_seconds + 240,
    # 직렬화는 json(안전)
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)


# 관측성(#93): 스캔 메트릭은 이 워커 프로세스에서 증가한다 → 워커가 자체 /metrics를
# 노출해야 Prometheus가 긁는다(backend의 /metrics엔 안 나옴). worker_process_init은
# 태스크가 실제로 도는 자식 프로세스에서 발화 → 그 프로세스의 카운터가 노출된다.
# concurrency=1이라 자식 1개 = 포트 1개. prometheus_client 없거나 포트충돌이면 조용히 skip.
@worker_process_init.connect
def _start_metrics_server(**_):
    try:
        from prometheus_client import start_http_server
        start_http_server(9200)
    except Exception:  # noqa: BLE001 - 미설치/포트충돌이어도 워커는 계속 동작
        pass
