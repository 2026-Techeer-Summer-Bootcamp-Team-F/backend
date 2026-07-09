# -*- coding: utf-8 -*-
"""Celery 앱 — 진화 스캔을 백그라운드 워커에서 실행. — ARCHITECTURE.md §3.4

FastAPI(웹, 빠른 응답)와 워커(무거운 스캔)는 별 프로세스. 둘을 잇는 브로커·결과저장은
Redis(§3.3 역할①②). `POST /scans`가 `run_scan.delay(id)`로 큐에 넣으면 워커가 꺼내 실행.

실행:
  워커  = celery -A app.celery_app worker --loglevel=info   (docker compose worker 서비스)
  큐잉  = from app.tasks import run_scan; run_scan.delay(scan_id)
"""
from celery import Celery

from .config import settings

celery_app = Celery(
    "redteam",
    broker=settings.redis_url,          # 큐(일감 배달)  — Redis
    backend=settings.redis_url,         # 결과 저장       — Redis
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
