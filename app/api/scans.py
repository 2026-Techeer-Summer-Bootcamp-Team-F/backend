# -*- coding: utf-8 -*-
"""§4 Scans — 스캔 시작/조회 + SSE 실시간 스트림. (담당: 너 = 엔진)

POST /scans 는 Scan 생성 + tasks.run_scan 을 백그라운드/Celery 로 던지고 즉시 반환.
"""
from fastapi import APIRouter

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", status_code=202)
def start_scan():
    """attack_types 받아 objectives 생성 + 스캔 큐잉. → tasks.run_scan. TODO"""
    return {"scan_id": 0, "status": "pending"}


@router.get("")
def list_scans():
    return []


@router.get("/{scan_id}")
def get_scan(scan_id: int):
    return {"scan_id": scan_id, "status": "TODO"}


@router.get("/{scan_id}/events")
def scan_events(scan_id: int, after: int = 0):
    """SSE — Redis pub/sub 구독해 진행상황 스트림(id=scan_events_id, ?after= 유실복구).
    ARCHITECTURE.md §10. TODO: StreamingResponse(text/event-stream)."""
    return {"todo": "SSE stream", "after": after}
