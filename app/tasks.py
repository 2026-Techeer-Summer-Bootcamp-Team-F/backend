# -*- coding: utf-8 -*-
"""비동기 스캔 태스크 (Celery). — ARCHITECTURE.md §5 · 계획 §2

`POST /scans` 가 `run_scan.delay(scan_id)` 로 Redis 큐에 넣으면, 별 프로세스인
워커가 꺼내 이 함수를 실행한다. 자체 DB 세션(요청 세션과 분리).

#36(관통 뼈대): status pending→running→done + scan_manager로 시작·완료 이벤트 발행.
목표별 진화(retrieve→select→mutate→fire→judge)는 #39에서 run_evolution 배선.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import select as sa_select

from .celery_app import celery_app
from .db import SessionLocal
from .engine.scan_manager import publish
from .models import AtlasTechnique, Objective, Scan, TargetProject
from .recon import profile_target, profile_to_atlas

log = logging.getLogger("redteam.tasks")


def _now():
    return datetime.now(timezone.utc)


def _run_recon(db, scan_id: int, target_id: int) -> dict:
    """정찰: 표적 프로파일 추출 → target_projects 갱신 + recon 기반 objectives 추가.

    - profile_target(ast+grep, 무료) → model/tools/defenses/rag/system_prompt
    - profile_to_atlas(규칙 §2-B-1) → 넣을 공격(atlas). 기존 목표와 dedup, 존재하는 atlas만.
    - 실패해도 스캔은 계속(정찰 없이 사용자 지정 목표로 진행).
    """
    profile = {}
    try:
        target = db.get(TargetProject, target_id)
        if target is None:
            return {}
        profile = profile_target(target)
        # 프로파일 저장(정찰필드)
        target.model = profile["model"] or target.model
        if profile["system_prompt"]:
            target.system_prompt = profile["system_prompt"]
        target.defences = {"detected": profile["defenses"]}
        target.tools = {"detected": profile["tools"]}
        target.rag_sources = {"detected": profile["rag_sources"]}
        db.commit()
        publish(scan_id, "progress",
                {"phase": "recon", "source": profile["source"],
                 "tools": profile["tools"], "defenses": profile["defenses"],
                 "rag_sources": profile["rag_sources"]}, db=db)

        # recon 기반 objectives 추가(기존과 dedup, DB에 존재하는 atlas만)
        recon_atlas = profile_to_atlas(profile)
        if recon_atlas:
            existing = {o.atlas_technique_id
                        for o in db.query(Objective).filter_by(scan_id=scan_id)}
            valid = set(db.scalars(
                sa_select(AtlasTechnique.id).where(AtlasTechnique.id.in_(recon_atlas))).all())
            for atlas_id in recon_atlas:
                if atlas_id in valid and atlas_id not in existing:
                    db.add(Objective(scan_id=scan_id, atlas_technique_id=atlas_id, status="pending"))
                    existing.add(atlas_id)
            db.commit()
    except Exception:
        db.rollback()
        log.exception("[worker] 정찰 실패(무시하고 진행): scan_id=%s", scan_id)
    return profile


@celery_app.task(name="run_scan")
def run_scan(scan_id: int) -> dict:
    """스캔 1건을 워커에서 실행. 상태 전이 + 이벤트 발행으로 처음~끝 관통.

    TODO(#39): objectives 순회에서 run_evolution(db, scan, obj, target) 배선.
    지금은 목표를 곧장 done 처리해 파이프 전체를 뚫는다(빈 껍데기 관통).
    """
    log.info("[worker] run_scan 수신: scan_id=%s", scan_id)
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.warning("[worker] scan 없음: scan_id=%s", scan_id)
            return {"scan_id": scan_id, "status": "missing"}

        # ── 멱등화(결정로그 §3-2): 이미 '끝난'(done/failed) 스캔의 재전달만 중복 실행 skip ──
        # RabbitMQ도 at-least-once라 같은 태스크가 두 번 배달될 수 있음. 단 'running'은
        # skip하지 않는다 — acks_late로 워커 급사 후 재전달된 경우라 다시 돌려야 크래시 복구가
        # 됨(running에서 skip하면 죽은 스캔이 영영 running에 갇힘).
        if scan.status in ("done", "failed"):
            log.info("[worker] 멱등 skip: scan_id=%s (status=%s)", scan_id, scan.status)
            return {"scan_id": scan_id, "status": scan.status, "skipped": True}

        # ── running ──
        scan.status = "running"
        scan.started_at = _now()
        db.commit()
        publish(scan_id, "log", {"message": "스캔 시작"}, db=db)

        # ── 정찰(recon): 표적 코드 프로파일링 → 프로파일 저장 + objectives 반영(#37) ──
        _run_recon(db, scan_id, scan.target_id)

        objectives = db.query(Objective).filter_by(scan_id=scan_id).all()
        publish(scan_id, "progress",
                {"phase": "start", "objectives": len(objectives)}, db=db)

        breached = 0
        for obj in objectives:
            # TODO(#39): breached = run_evolution(db, scan, obj, target)
            obj.status = "done"
            db.commit()
            publish(scan_id, "progress", {"phase": "objective_done"},
                    db=db, objective_id=obj.objective_id)

        # ── done ──
        scan.status = "done"
        scan.finished_at = _now()
        db.commit()
        publish(scan_id, "done",
                {"status": "done", "objectives": len(objectives), "breached": breached}, db=db)
        log.info("[worker] run_scan 완료: scan_id=%s (objectives=%s)", scan_id, len(objectives))
        return {"scan_id": scan_id, "status": "done"}

    except Exception:
        # 실패해도 상태를 failed로 남기고 이벤트 발행(사용자에게 보임).
        log.exception("[worker] run_scan 실패: scan_id=%s", scan_id)
        try:
            db.rollback()          # commit 실패 시 세션이 롤백대기 → 재사용 전 정리(안 하면 PendingRollbackError)
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.status = "failed"
                scan.finished_at = _now()
                db.commit()
                publish(scan_id, "done", {"status": "failed"}, db=db)
        except Exception:
            log.exception("[worker] 실패 상태 기록도 실패: scan_id=%s", scan_id)
        return {"scan_id": scan_id, "status": "failed"}
    finally:
        db.close()
