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
    # 직렬화는 json(안전)
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)
