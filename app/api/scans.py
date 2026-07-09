# -*- coding: utf-8 -*-
"""§4 Scans — 스캔 시작/조회 + SSE 실시간 스트림. (담당: 너 = 엔진)

POST /scans 는 Scan 생성 + objectives 저장 + tasks.run_scan 을 Celery 로 던지고
즉시 202 반환(사용자 안 기다림). 실제 진화는 워커(별 프로세스)가 수행. — 계획 §1
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AtlasTechnique, Objective, Scan, TargetProject
from ..schemas import ScanCreate
from ..tasks import run_scan

router = APIRouter(prefix="/scans", tags=["scans"])


def _resolve_objective_atlas(db: Session, config: dict) -> list:
    """요청 attack_types → objectives(atlas 기법 id) 변환.

    #36(관통 뼈대)에선 "이미 atlas 마스터에 존재하는 id"만 objective로 만든다
    (FK 위반 방지). 정찰 프로파일→공격유형 정식 매핑표는 #37에서 engine/attack_types.py로.
    보통 로컬 atlas 테이블이 비어 있으면 0개 → '빈 목표라도 관통'(이슈 완료기준).
    """
    wanted = config.get("attack_types") or []
    if not wanted:
        return []
    # 존재하는 atlas id만 통과(중복 제거). 필터를 SQL로 밀어 전체 스캔 회피.
    existing = set(db.scalars(
        sa_select(AtlasTechnique.id).where(AtlasTechnique.id.in_(wanted))
    ).all())
    return [a for a in dict.fromkeys(wanted) if a in existing]


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
def scan_events(scan_id: int, after: int = 0):
    """SSE — Redis pub/sub 구독해 진행상황 스트림(id=scan_events_id, ?after= 유실복구).
    ARCHITECTURE.md §10. TODO(#41): StreamingResponse(text/event-stream)."""
    return {"todo": "SSE stream", "after": after}
