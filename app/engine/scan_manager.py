# -*- coding: utf-8 -*-
"""스캔 실시간 이벤트 — persist-then-publish. — ARCHITECTURE.md §10, 계획 §5·§8-A

원칙: SSE로 그냥 쏘면 놓친 이벤트는 사라짐 → ① scan_events(DB)에 먼저 저장(순번=id,
유실복구 원본) → ② Redis 채널로 방송(실시간). 사용자는 실시간(Redis)으로 보되, 끊기면
DB에서 순번(?after=)으로 복구. Celery 워커(진화)와 FastAPI(SSE)가 별 프로세스라
in-memory 큐 불가 → Redis pub/sub 필수(§3.3 역할③).
"""
import json
import logging

import redis

from ..config import settings
from ..models import ScanEvent

log = logging.getLogger(__name__)

# 방송용 Redis 연결(발행 전용, 동기). 워커·API 어디서든 import해 씀.
# 타임아웃: Redis 지연·네트워크 문제 시 동기 publish()가 오래 막히지 않게 상한.
_redis = redis.Redis.from_url(
    settings.redis_url, socket_timeout=5, socket_connect_timeout=5
)


def channel(scan_id: int) -> str:
    """스캔별 방송 채널 이름. FastAPI SSE가 여기를 구독한다."""
    return f"channel:scan:{scan_id}"


def publish(scan_id: int, event_type: str, payload: dict,
            db=None, objective_id=None) -> dict:
    """이벤트 1건: ① DB 저장(있으면) → ② Redis 방송. 저장된 payload(순번 id 포함) 반환.

    - event_type: log|progress|attempt|finding|done (API-명세 §4)
    - db 주면 scan_events에 영속화(유실복구 원본). None이면 방송만.
    - objective_id 주면 payload에 함께(어느 목표 이벤트인지).
    """
    # payload를 먼저 펴고 event를 나중에 → 호출자 payload에 "event"가 있어도 event_type이 이김
    data = {**payload, "event": event_type}
    if objective_id is not None:
        data["objective_id"] = objective_id
    # ① persist: DB에 먼저(순번=scan_events_id → SSE ?after= 유실복구 원본)
    if db is not None:
        ev = ScanEvent(scan_id=scan_id, payload=data)
        db.add(ev)
        db.commit()
        db.refresh(ev)
        data["id"] = ev.scan_events_id       # 순번(SSE Last-Event-ID)
    # ② publish: Redis 채널로 방송(구독 중인 SSE가 즉시 받음).
    # 방송 실패는 치명적이지 않음 — 이미 ①에서 DB에 남았으니 SSE가 ?after=로 복구.
    # 여기서 예외를 삼켜야 Redis 끊김이 진화루프를 중단시키지 않음(설계 §8-A).
    try:
        _redis.publish(channel(scan_id), json.dumps(data, ensure_ascii=False))
    except redis.RedisError:
        log.exception("Redis publish 실패(무시): scan_id=%s, event=%s", scan_id, event_type)
    return data
