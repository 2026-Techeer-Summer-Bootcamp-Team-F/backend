# -*- coding: utf-8 -*-
"""§4 Scans — 스캔 시작/조회 + SSE 실시간 스트림. (담당: 너 = 엔진)

POST /scans 는 Scan 생성 + objectives 저장 + tasks.run_scan 을 Celery 로 던지고
즉시 202 반환(사용자 안 기다림). 실제 진화는 워커(별 프로세스)가 수행. — 계획 §1
"""
import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import delete as sa_delete
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..authz import scan_owned_by_uid, scan_owned_or_404
from ..db import SessionLocal, get_db
from ..deps import get_current_user
from ..models import (
    AtlasTechnique,
    Attempt,
    Finding,
    Objective,
    Scan,
    ScanEvent,
    ScanReport,
    TargetProject,
    User,
)
from ..recon import attack_types_to_atlas
from ..schemas import ScanCreate
from ..security import decode_access_token
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
def start_scan(body: ScanCreate, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    """스캔 트리거: scans 저장(pending) → objectives 저장 → Celery 큐잉 → 202.

    소유권(#91): 본인 소유의 표적에만 스캔을 걸 수 있다. 남의/없는/삭제된 표적은 404
    (존재 은닉).
    """
    target = db.get(TargetProject, body.target_id)
    if (target is None or target.deleted_at is not None
            or target.user_id != user.user_id):
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
def list_scans(db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    """내 스캔 목록(대시보드). 소유권(#91): 본인 표적의 스캔만 반환(최신순)."""
    scans = db.scalars(
        sa_select(Scan)
        .join(TargetProject, Scan.target_id == TargetProject.target_id)
        .where(TargetProject.user_id == user.user_id)
        .order_by(Scan.scan_id.desc()).limit(50)).all()
    return [{"scan_id": s.scan_id, "target_id": s.target_id, "status": s.status,
             "created_at": s.created_at} for s in scans]


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db),
             user: User = Depends(get_current_user)):
    """스캔 1건: 상태 + 진행 + objectives 개수/상태(진행상황 관찰용). 소유권 검증(#91)."""
    scan = scan_owned_or_404(db, scan_id, user)
    objectives = db.scalars(sa_select(Objective).where(Objective.scan_id == scan_id)).all()
    return {
        "scan_id": scan.scan_id, "target_id": scan.target_id, "status": scan.status,
        "progress": scan.progress or {},
        "started_at": scan.started_at, "finished_at": scan.finished_at,
        "objectives": [{"objective_id": o.objective_id,
                        "atlas_technique_id": o.atlas_technique_id,
                        "status": o.status} for o in objectives],
    }

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """과거 스캔 기록 삭제.

    - 스캔이 없으면 404
    - 다른 사용자의 스캔이면 403
    - pending/running 상태이면 403
    - 완료된 스캔은 관련 기록까지 삭제하고 204 반환
    """
    scan = db.get(Scan, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="스캔 없음",
        )

    # Scan에는 user_id가 없으므로 프로젝트를 통해 소유권 확인
    target = db.get(TargetProject, scan.target_id)

    # 프로젝트 행이 아예 없을 때만 404. 소프트삭제(deleted_at)된 프로젝트라도
    # 소유자는 과거 스캔 기록을 정리할 수 있어야 하므로 아래 소유권 검증으로 넘긴다.
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="프로젝트 없음",
        )

    if target.user_id != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="본인 프로젝트의 스캔만 삭제할 수 있습니다.",
        )

    # 진행 중인 스캔은 삭제 금지
    if scan.status in ("pending", "running"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="실행 중인 스캔은 삭제할 수 없습니다.",
        )

    try:
        # 스캔에 연결된 공격 목표 ID 조회
        objective_ids = db.scalars(
            sa_select(Objective.objective_id).where(
                Objective.scan_id == scan_id
            )
        ).all()

        if objective_ids:
            # 목표에 연결된 공격 시도 ID 조회
            attempt_ids = db.scalars(
                sa_select(Attempt.attempt_id).where(
                    Attempt.objective_id.in_(objective_ids)
                )
            ).all()

            if attempt_ids:
                # 취약점 기록 삭제
                db.execute(
                    sa_delete(Finding).where(
                        Finding.attempt_id.in_(attempt_ids)
                    )
                )

                # 공격 시도 삭제
                db.execute(
                    sa_delete(Attempt).where(
                        Attempt.attempt_id.in_(attempt_ids)
                    )
                )

            # 공격 목표 삭제
            db.execute(
                sa_delete(Objective).where(
                    Objective.objective_id.in_(objective_ids)
                )
            )

        # 스캔 이벤트 삭제
        db.execute(
            sa_delete(ScanEvent).where(
                ScanEvent.scan_id == scan_id
            )
        )

        # 스캔 리포트 삭제
        db.execute(
            sa_delete(ScanReport).where(
                ScanReport.scan_id == scan_id
            )
        )

        # 마지막으로 스캔 삭제
        db.execute(
            sa_delete(Scan).where(
                Scan.scan_id == scan_id
            )
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    """스캔 취소 — status=cancelled로 표시. 워커(run_scan)가 목표 사이에서 감지해 중단. — §4

    소유권 검증(#91): 본인 스캔만 취소 가능(남의/없는 스캔은 404).
    """
    scan = scan_owned_or_404(db, scan_id, user)
    if scan.status in ("done", "failed", "cancelled"):
        return {"scan_id": scan_id, "status": scan.status, "stop_reason": "already_terminal"}
    scan.status = "cancelled"
    db.commit()
    # SSE로도 알림(폴링 중인 프론트가 즉시 종료 감지)
    from ..engine.scan_manager import publish
    publish(scan_id, "done", {"status": "cancelled", "stop_reason": "cancelled"}, db=db)
    return {"scan_id": scan_id, "status": "cancelled", "stop_reason": "cancelled"}


@router.get("/{scan_id}/stream")
async def scan_stream(scan_id: int, request: Request, after: int = 0, token: str = ""):
    """SSE(#41) — scan_events(DB)를 폴링해 진행상황 스트림. (API-명세 §5 `/scans/{id}/stream`)

    ⚠️ 경로는 명세·프론트(EventSource)에 맞춰 `/stream`. (구 `/events`에서 정정, 2026-07-10)
    TODO(auth): 명세는 `?token=<jwt>`(EventSource가 헤더 못 실음) — 팀원 JWT 연동 후.

    - 각 이벤트 `id=scan_events_id` → 클라가 끊기면 이어받기. 브라우저 EventSource는 자동
      재접속 때 `Last-Event-ID` 헤더로 마지막 id를 보내므로 이를 `?after=`보다 우선한다.
    - 워커가 scan_events에 저장하면 여기서 1초 주기로 `id>after` 조회해 흘려보냄.
    - `event==done` 이벤트를 보내면 스트림 종료. 스캔이 이미 done/failed면 곧장 종료.
    - 무이벤트가 MAX_IDLE(초) 지속되면 스트림 종료(연결 누수 방지).
    """
    MAX_IDLE = 300  # 새 이벤트 없이 5분(=300×1s) 지나면 스트림 닫음

    # SSE 인증: EventSource는 Authorization 헤더를 못 실으므로 `?token=<jwt>`로 검증(#41).
    # 없거나 무효면 401. (프론트 RunScanPage가 이미 ?token=로 붙여 보냄)
    try:
        payload = decode_access_token(token)
    except Exception:  # noqa: BLE001 - 만료/무효/빈값 전부 401
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "토큰 없음 또는 무효") from None
    sub = payload.get("sub")
    uid = int(sub) if sub else None

    # 브라우저 EventSource 자동 재접속 시 보내는 Last-Event-ID 헤더를 ?after=보다 우선
    lei = request.headers.get("Last-Event-ID")
    if lei and lei.isdigit():
        after = int(lei)

    # 연결 시 소유권 확인(#91): 본인 스캔이 아니거나 없으면 404(존재 은닉).
    # 동기 DB 조회는 to_thread로 빼 이벤트루프를 막지 않음.
    def _owned():
        with SessionLocal() as db0:
            return uid is not None and scan_owned_by_uid(db0, scan_id, uid)
    if not await asyncio.to_thread(_owned):
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
