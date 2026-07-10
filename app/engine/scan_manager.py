# -*- coding: utf-8 -*-
"""스캔 실시간 이벤트 — persist(DB 저장). — ARCHITECTURE.md §10, 결정로그-2026-07-10

원칙(2026-07-10 변경): 워커는 이벤트를 scan_events(DB)에 저장(순번=scan_events_id)만 한다.
실시간 전달은 FastAPI SSE가 그 테이블을 폴링(scan_events_id > after)해서 흐른다.
Redis pub/sub 안 씀 — 컨슈머가 잠깐 내려가면 유실되므로 DB 폴링으로 대체. DB가
유실복구 원본이자 SSE 데이터 출처(끊겨도 ?after=로 순번 재조회).
"""
import logging

from ..models import ScanEvent

log = logging.getLogger(__name__)


def publish(scan_id: int, event_type: str, payload: dict,
            db=None, objective_id=None) -> dict:
    """이벤트 1건을 scan_events(DB)에 저장. 저장된 payload(순번 id 포함)를 반환.

    - event_type: log|progress|attempt|finding|done (API-명세 §4)
    - db 주면 scan_events에 영속화(SSE 폴링 소스). None이면 저장 없이 dict만 구성.
    - objective_id 주면 payload에 함께 실어 어느 목표 이벤트인지 표시.
    실시간 전달은 SSE 엔드포인트(scans.py)가 이 테이블을 id>after로 폴링해 수행하므로
    여기서는 방송하지 않는다(브로커=RabbitMQ, 실시간=DB폴링으로 역할 분리).
    """
    # payload를 먼저 펴고 event를 나중에 → 호출자 payload에 "event"가 있어도 event_type이 이김
    data = {**payload, "event": event_type}
    if objective_id is not None:
        data["objective_id"] = objective_id
    # persist: DB에 저장(순번=scan_events_id → SSE ?after= 유실복구 원본이자 폴링 소스)
    if db is not None:
        ev = ScanEvent(scan_id=scan_id, payload=data)
        db.add(ev)
        db.commit()
        db.refresh(ev)
        data["id"] = ev.scan_events_id       # 순번(SSE Last-Event-ID / ?after=)
    return data
