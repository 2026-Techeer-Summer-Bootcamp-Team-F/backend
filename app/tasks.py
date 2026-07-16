# -*- coding: utf-8 -*-
"""비동기 스캔 태스크 (Celery). — ARCHITECTURE.md §5 · 계획 §2

`POST /scans` 가 `run_scan.delay(scan_id)` 로 Redis 큐에 넣으면, 별 프로세스인
워커가 꺼내 이 함수를 실행한다. 자체 DB 세션(요청 세션과 분리).

#36(관통 뼈대): status pending→running→done + scan_manager로 시작·완료 이벤트 발행.
목표별 진화(retrieve→select→mutate→fire→judge)는 #39에서 run_evolution 배선.
"""
import logging
import time
from datetime import datetime, timezone

from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import worker_ready
from sqlalchemy import select as sa_select

from . import metrics
from .celery_app import celery_app
from .db import SessionLocal
from .engine.orchestrator import run_evolution
from .engine.scan_manager import publish
from .models import AtlasTechnique, Objective, Scan, TargetProject
from .recon import profile_target, profile_to_atlas
from .engine.code_scanner import run_code_scan

log = logging.getLogger("redteam.tasks")


@worker_ready.connect
def _reset_stale_scans(**_):
    """워커 부팅 시 좀비 스캔 자동 정리 — 이전 워커가 물고 있다 끊긴(running) 또는 큐에서
    유실된(pending) 스캔을 failed로 확정한다.

    `task_acks_late=True`라 워커가 죽으면 in-flight 태스크가 재전달되는데, 그 스캔이
    아직 running 상태면 run_scan이 skip하지 않고 다시 실행 → 접근 불가/무한 표적을
    또 붙잡아 워커를 점유한다(좀비). 부팅 시 running/pending을 failed로 박아두면
    재전달돼도 run_scan이 done/failed는 skip하므로 좀비가 되살아나지 못한다.
    (이 시그널은 워커 프로세스에서만 발화 — 웹 backend엔 영향 없음)
    """
    try:
        db = SessionLocal()
        n = (db.query(Scan)
               .filter(Scan.status.in_(["pending", "running"]))
               .update({Scan.status: "failed"}, synchronize_session=False))
        db.commit()
        db.close()
        if n:
            log.info("[worker] 부팅 정리: 좀비 스캔 %s개 → failed", n)
    except Exception:
        log.exception("[worker] 부팅 정리 실패(계속)")


def _now():
    return datetime.now(timezone.utc)


def _run_recon(db, scan_id: int, target_id: int) -> dict:
    """정찰: 표적 프로파일 추출 → target_projects 갱신 + recon 기반 objectives 추가.

    - profile_target(ast+grep, 무료) → model/tools/defenses/rag/system_prompt
    - profile_to_atlas(규칙 §2-B-1) → 넣을 공격(atlas). 기존 목표와 dedup, 존재하는 atlas만.
    - 실패해도 스캔은 계속(정찰 없이 사용자 지정 목표로 진행).
    """
    profile = {}

    def _log(msg):
        publish(scan_id, "log", {"message": msg}, db=db)

    try:
        target = db.get(TargetProject, target_id)
        if target is None:
            return {}
        _log("정찰 시작 — 표적 앱 프로파일링")
        profile = profile_target(target)
        _log("표적 구성 파악 중 (모델·도구·방어·RAG 식별)")
        # 프로파일 저장(정찰필드)
        target.model = profile["model"] or target.model
        if profile["system_prompt"]:
            target.system_prompt = profile["system_prompt"]
        target.defences = {"detected": profile["defenses"]}
        target.tools = {"detected": profile["tools"]}
        target.rag_sources = {"detected": profile["rag_sources"]}
        # 코드 위치 스캔 — 표적 소유자의 GitHub 토큰으로 fetch(비공개 조직 레포 대응).
        # 토큰이 없거나 빈 결과면 기존 code_locations를 덮어쓰지 않는다(등록 정찰 결과 보호).
        all_atlas_ids = [
            "AML.T0054", "AML.T0051.000", "AML.T0051.001",
            "AML.T0056", "AML.T0057", "AML.T0053",
        ]
        token = ""
        try:
            from .security import decrypt_token
            from .models import User
            owner = db.get(User, target.user_id)
            if owner and owner.access_token_enc:
                token = decrypt_token(owner.access_token_enc) or ""
        except Exception:  # noqa: BLE001 - 토큰 복호화 실패 → 토큰 없이 진행
            token = ""
        locs = run_code_scan(target.repo_url, all_atlas_ids, token, on_log=_log)
        if locs:
            target.code_locations = locs
        db.commit()
        _log("recon 완료 — 진화 루프 시작")
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
    started = False        # running까지 진입했는지(메트릭 in_progress/duration 계상 여부)
    t0 = None
    result_status = None   # 종료 상태(done/failed/cancelled) — finally에서 카운트
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.warning("[worker] scan 없음: scan_id=%s", scan_id)
            return {"scan_id": scan_id, "status": "missing"}

        # ── 멱등화(결정로그 §3-2): 이미 '끝난' 스캔의 재전달을 중복 실행 skip ──
        # RabbitMQ도 at-least-once라 같은 태스크가 두 번 배달될 수 있음. done/failed/
        # cancelled는 모두 종료 상태 → 재전달돼도 절대 재실행하지 않는다. (특히 cancelled를
        # 빠뜨리면 취소된 좀비 스캔이 되살아나 워커를 점유함 — 실경험). 단 'running'은
        # skip하지 않는다 — acks_late로 워커 급사 후 재전달된 경우라 다시 돌려야 크래시 복구가
        # 됨(running에서 skip하면 죽은 스캔이 영영 running에 갇힘).
        if scan.status in ("done", "failed", "cancelled"):
            log.info("[worker] 멱등 skip: scan_id=%s (status=%s)", scan_id, scan.status)
            return {"scan_id": scan_id, "status": scan.status, "skipped": True}

        # ── running ──
        scan.status = "running"
        scan.started_at = _now()
        db.commit()
        metrics.SCAN_STARTED.inc()               # 스캔 시작 카운트 (#93)
        metrics.SCANS_IN_PROGRESS.inc()          # 진행중 게이지 +1
        started = True
        t0 = time.monotonic()
        publish(scan_id, "log", {"message": "스캔 시작"}, db=db)

        # ── 정찰(recon): 표적 코드 프로파일링 → 프로파일 저장 + objectives 반영(#37) ──
        _run_recon(db, scan_id, scan.target_id)

        objectives = db.query(Objective).filter_by(scan_id=scan_id).all()
        publish(scan_id, "progress",
                {"phase": "start", "objectives": len(objectives)}, db=db)

        # 표적 + 카나리(성공 판정 FLAG) — target.config 우선, 없으면 scan.config
        target = db.get(TargetProject, scan.target_id)
        canary = ((target.config or {}).get("canary")
                  or (scan.config or {}).get("canary")) if target else None

        breached = 0
        for obj in objectives:
            # 취소 감지(#56): 사용자가 POST /cancel로 status=cancelled 하면 목표 사이에서 중단
            db.refresh(scan)
            if scan.status == "cancelled":
                log.info("[worker] 스캔 취소 감지 — 중단: scan_id=%s", scan_id)
                result_status = "cancelled"
                return {"scan_id": scan_id, "status": "cancelled"}
            # 진화 루프(#39): retrieve→select→mutate→fire→judge→elitism. 뚫으면 Finding+breached.
            try:
                if run_evolution(db, scan_id, obj, target, canary):
                    breached += 1
            except SoftTimeLimitExceeded:
                # 스캔 전체 시간초과 → 이 목표에서 삼키지 말고 바깥으로 던져 스캔을 failed 종료
                # (안 그러면 다음 목표로 넘어가 hard time_limit에 강제 종료 → acks_late 재전달 루프)
                raise
            except Exception:
                log.exception("[worker] objective 진화 실패(계속): objective_id=%s", obj.objective_id)
                obj.status = "failed"
                db.commit()
            publish(scan_id, "progress", {"phase": "objective_done", "status": obj.status},
                    db=db, objective_id=obj.objective_id)

        # ── done ── (취소된 경우 done으로 덮어쓰지 않음)
        db.refresh(scan)
        if scan.status == "cancelled":
            result_status = "cancelled"
            return {"scan_id": scan_id, "status": "cancelled"}
        scan.status = "done"
        scan.finished_at = _now()
        db.commit()
        publish(scan_id, "done",
                {"status": "done", "objectives": len(objectives), "breached": breached}, db=db)
        try:  # AI 요약 사전 생성+캐싱 — 리포트 첫 조회 시 Haiku 지연(2~5초) 제거
            from .api.results import warm_summary
            warm_summary(db, scan)
        except Exception:  # noqa: BLE001 - 요약 실패는 스캔 성공에 영향 없음(다음 조회 때 재생성)
            log.warning("[worker] 요약 사전생성 실패: scan_id=%s", scan_id, exc_info=True)
        log.info("[worker] run_scan 완료: scan_id=%s (objectives=%s)", scan_id, len(objectives))
        result_status = "done"
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
        result_status = "failed"
        return {"scan_id": scan_id, "status": "failed"}
    finally:
        # 진행중 게이지 -1 + 소요시간 + 종료상태 카운트(모든 종료경로 공통). (#93)
        if started:
            metrics.SCANS_IN_PROGRESS.dec()
            if t0 is not None:
                metrics.SCAN_DURATION.observe(time.monotonic() - t0)
            metrics.SCAN_FINISHED.labels(status=result_status or "unknown").inc()
        # Langfuse 대기 트레이스 강제 전송(키 없으면 no-op) — 데모 즉시 반영
        try:
            from .observability import flush as _lf_flush
            _lf_flush()
        except Exception:  # noqa: BLE001 - 관측성 flush 실패는 스캔에 영향 없음
            pass
        db.close()
