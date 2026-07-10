# -*- coding: utf-8 -*-
"""§4 Scans — 스캔 시작/조회 + SSE 실시간 스트림. (담당: 너 = 엔진)

POST /scans 는 Scan 생성 + objectives 저장 + tasks.run_scan 을 Celery 로 던지고
즉시 202 반환(사용자 안 기다림). 실제 진화는 워커(별 프로세스)가 수행. — 계획 §1
"""
import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..db import SessionLocal, get_db
from ..models import AtlasTechnique, Objective, Scan, ScanEvent, TargetProject
from ..recon import attack_types_to_atlas
from ..schemas import ScanCreate
from ..tasks import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])


def _resolve_objective_atlas(db: Session, config: dict) -> list:
    """요청 attack_types(문자열) → objectives(atlas 기법 id) 변환.

    recon.attack_types_to_atlas로 매핑(§2-B-1) 후, DB에 실제 존재하는 atlas만 통과
    (FK 위반 방지). 정찰 기반 추가 목표는 워커(#37)가 스캔 중에 더한다.
    """
    wanted = attack_types_to_atlas(config.get("attack_types"))
    if not wanted:
        return []
    # 존재하는 atlas id만 통과. 필터를 SQL로 밀어 전체 스캔 회피.
    existing = set(db.scalars(
        sa_select(AtlasTechnique.id).where(AtlasTechnique.id.in_(wanted))
    ).all())
    return [a for a in wanted if a in existing]


@router.post("", status_code=202)
def start_scan(body: ScanCreate, db: Session = Depends(get_db)):
    """스캔 트리거: scans 저장(pending) → objectives 저장 → Celery 큐잉 → 202.

    TODO(auth): 소유권 검증(get_current_user)은 팀원 JWT 완성 후. 지금은 표적 존재만
    확인하고 관통(껍데기 데모). — 계획 §1의 크로스팀 의존성.
    """
    target = db.get(TargetProject, body.target_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "표적 프로젝트 없음")

    scan = Scan(target_id=target.target_id, status="pending", config=body.config)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # attack_types → objectives(atlas). #36은 존재하는 것만(빈 목표라도 관통).
    # TODO(#37): 매핑표 완성 후 "objective 0개면 422(공격유형 최소 1개)"로 거절.
    #            #36(껍데기)에선 매핑표가 없어 항상 0개라 관대하게 통과시킨다.
    for atlas_id in _resolve_objective_atlas(db, body.config):
        db.add(Objective(scan_id=scan.scan_id, atlas_technique_id=atlas_id, status="pending"))
    db.commit()

    run_scan.delay(scan.scan_id)          # ★ Celery: 큐에 넣고 즉시 반환(워커가 실행)
    return {"scan_id": scan.scan_id, "status": scan.status}


@router.get("")
def list_scans(db: Session = Depends(get_db)):
    """내 스캔 목록(대시보드). TODO(auth): user 필터. 지금은 최신순 전체."""
    scans = db.scalars(sa_select(Scan).order_by(Scan.scan_id.desc()).limit(50)).all()
    return [{"scan_id": s.scan_id, "target_id": s.target_id, "status": s.status,
             "created_at": s.created_at} for s in scans]


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """스캔 1건: 상태 + 진행 + objectives 개수/상태(진행상황 관찰용)."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔 없음")
    objectives = db.scalars(sa_select(Objective).where(Objective.scan_id == scan_id)).all()
    return {
        "scan_id": scan.scan_id, "target_id": scan.target_id, "status": scan.status,
        "progress": scan.progress or {},
        "started_at": scan.started_at, "finished_at": scan.finished_at,
        "objectives": [{"objective_id": o.objective_id,
                        "atlas_technique_id": o.atlas_technique_id,
                        "status": o.status} for o in objectives],
    }


@router.get("/{scan_id}/events")
async def scan_events(scan_id: int, after: int = 0):
    """SSE(#41) — scan_events(DB)를 폴링해 진행상황 스트림. (2026-07-10: Redis pub/sub→DB폴링)

    - 각 이벤트 `id=scan_events_id` → 클라가 끊기면 `?after=<마지막 id>`로 이어받기(Last-Event-ID).
    - 워커가 scan_events에 저장하면 여기서 1초 주기로 `id>after` 조회해 흘려보냄.
    - `event==done` 이벤트를 보내면 스트림 종료. 스캔이 이미 done/failed면 곧장 종료.
    - 무이벤트가 MAX_IDLE(초) 지속되면 스트림 종료(연결 누수 방지).
    """
    MAX_IDLE = 300  # 새 이벤트 없이 5분(=300×1s) 지나면 스트림 닫음

    # 연결 시 스캔 존재 확인(없으면 404). 동기 DB 조회는 to_thread로 빼 이벤트루프를 막지 않음.
    def _exists():
        with SessionLocal() as db0:
            return db0.get(Scan, scan_id) is not None
    if not await asyncio.to_thread(_exists):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔 없음")

    def _poll(after_id: int):
        # 동기 DB 조회(이벤트 목록 + 종료여부). asyncio.to_thread로 실행해 이벤트루프를 막지 않음.
        with SessionLocal() as db:
            rows = db.scalars(
                sa_select(ScanEvent)
                .where(ScanEvent.scan_id == scan_id, ScanEvent.scan_events_id > after_id)
                .order_by(ScanEvent.scan_events_id)
            ).all()
            events = [(r.scan_events_id, r.payload) for r in rows]
            terminal = False
            if not events:
                scan = db.get(Scan, scan_id)
                terminal = scan is not None and scan.status in ("done", "failed")
            return events, terminal

    async def event_stream():
        last = after
        idle = 0
        while True:
            events, terminal = await asyncio.to_thread(_poll, last)
            if events:
                idle = 0
                for eid, payload in events:
                    last = eid
                    yield f"id: {eid}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                    if isinstance(payload, dict) and payload.get("event") == "done":
                        return
            else:
                if terminal:           # 스캔 끝났고 남은 이벤트 없음 → 종료(없는 done 대기 방지)
                    return
                idle += 1
                if idle >= MAX_IDLE:
                    return
                yield ": keep-alive\n\n"   # 프록시 타임아웃 방지용 주석 프레임
            await asyncio.sleep(1)

    return StreamingResponse(event_stream(), media_type="text/event-stream")
