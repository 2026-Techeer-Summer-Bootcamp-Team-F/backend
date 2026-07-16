# -*- coding: utf-8 -*-
"""§5 Results — 리포트·히트맵·Findings·AI요약. (담당: 엔진/결과) — API-명세.md §5

전부 읽기 전용 집계 쿼리(scans/objectives/attempts/findings 조인). 결과 = 대시보드 원본.
AI 요약은 키 없으면 템플릿, ANTHROPIC_API_KEY 있으면 Haiku로 자동 업그레이드(#40·#42).
"""
import json

from fastapi import APIRouter, Depends
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..authz import scan_owned_or_404
from ..config import settings
from ..db import get_db
from ..deps import get_current_user
from ..mitigations import get_mitigation
from ..models import (Attempt, AtlasTechnique, Finding, Objective, ScanReport,
                      TargetProject, User)

router = APIRouter(prefix="/scans", tags=["results"])

_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 5}

# 히트맵 스택바용: 안 뚫린 시도 중 fitness가 이 값 이상이면 '부분(근접)', 미만이면 '방어'
_PARTIAL_MIN = 0.5


def _heat_status(status: str) -> str:
    """objective status → 프론트 히트맵 enum(breached|safe|untested).

    프론트 계약(scans.ts HeatmapTechnique)은 3값만 씀:
    - breached : 뚫림
    - untested : 아직 공격 안 함(pending/running)
    - safe     : 공격했으나 안 뚫림(safe/exhausted/failed)
    """
    if status == "breached":
        return "breached"
    if status in ("pending", "running"):
        return "untested"
    return "safe"


def _collect(db: Session, scan_id: int):
    """스캔의 objectives / attempts / findings를 한 번에 모아 반환(조인 재사용)."""
    objs = db.scalars(sa_select(Objective).where(Objective.scan_id == scan_id)).all()
    obj_ids = [o.objective_id for o in objs]
    attempts = db.scalars(
        sa_select(Attempt).where(Attempt.objective_id.in_(obj_ids))).all() if obj_ids else []
    at_ids = [a.attempt_id for a in attempts]
    findings = db.scalars(
        sa_select(Finding).where(Finding.attempt_id.in_(at_ids))).all() if at_ids else []
    return objs, attempts, findings


@router.get("/{scan_id}/report")
def report(scan_id: int, db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    """대시보드 통계: 목표/시도/침투/취약점 + 위험도(심각도 가중). 소유권 검증(#91). — §5"""
    scan = scan_owned_or_404(db, scan_id, user)
    return _report_core(db, scan)


def _report_core(db: Session, scan) -> dict:
    """report() 계산 코어(소유권 검증 제외) — 엔드포인트·워커 요약 공용."""
    scan_id = scan.scan_id
    objs, attempts, findings = _collect(db, scan_id)
    breached_objs = sum(1 for o in objs if o.status == "breached")
    sev_counts: dict = {}
    risk = 0
    for f in findings:
        sev = f.severity or "low"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        risk += _SEV_WEIGHT.get(sev, 5)
    total = len(objs)
    # 응답 형태 = API-명세 §5 + 프론트 ScanReport (top-level 파생값 + stats{}).
    # report_id는 scan_reports 스냅샷 테이블을 안 써서 파생(on-the-fly) → null.
    return {
        "report_id": None,
        "scan_id": scan_id,
        "status": scan.status,
        "total_objectives": total,
        "breached_count": breached_objs,                          # 뚫린 '목표' 수
        "coverage_pct": round(breached_objs / total * 100, 1) if total else 0.0,
        "severity_counts": sev_counts,
        "risk_score": float(min(100, risk)),
        "stats": {                                                # 대시보드 큰 숫자용
            "total_attempts": len(attempts),
            "breached_attempts": sum(1 for a in attempts if a.breached),  # 뚫린 '시도' 수
            "findings": len(findings),
        },
    }


@router.get("/{scan_id}/heatmap")
def heatmap(scan_id: int, db: Session = Depends(get_db),
            user: User = Depends(get_current_user)):
    """ATLAS 기법별 침투 히트맵 — objective별 상태 + 최고 fitness. 소유권 검증(#91). — §5"""
    scan_owned_or_404(db, scan_id, user)
    objs, attempts, _ = _collect(db, scan_id)
    # objective별 최고 fitness + 시도 횟수
    best: dict = {}
    att_count: dict = {}
    dist: dict = {}  # objective_id -> [defended, partial, breached] 시도 결과 분포
    for a in attempts:
        oid = a.objective_id
        best[oid] = max(best.get(oid, 0.0), a.fitness or 0.0)
        att_count[oid] = att_count.get(oid, 0) + 1
        d, p, b = dist.get(oid, (0, 0, 0))
        if a.breached:
            b += 1
        elif (a.fitness or 0.0) >= _PARTIAL_MIN:
            p += 1
        else:
            d += 1
        dist[oid] = (d, p, b)
    cells = []
    for o in objs:
        tech = db.get(AtlasTechnique, o.atlas_technique_id)
        cells.append({
            "atlas_technique_id": o.atlas_technique_id,
            "name": tech.name if tech else o.atlas_technique_id,
            "tactic": tech.tactic if tech else "",
            "status": _heat_status(o.status),                # 프론트 enum(breached|safe|untested)
            "breached": o.status == "breached",
            "attempts": att_count.get(o.objective_id, 0),    # 프론트 계약: objective별 시도 횟수
            "best_score": round(best.get(o.objective_id, 0.0), 3),
            # 스택바용 시도 결과 분포(방어/부분/뚫림). 기존 필드 유지 → 하위호환.
            "dist": dict(zip(
                ("defended", "partial", "breached"),
                dist.get(o.objective_id, (0, 0, 0)),
            )),
        })
    return {"scan_id": scan_id, "cells": cells}


@router.get("/{scan_id}/findings")
def findings(scan_id: int, db: Session = Depends(get_db),
             user: User = Depends(get_current_user)):
    """취약점 목록 + 증거 + 완화책(finding→attempt→objective→atlas 조인). 소유권 검증(#91). — §5"""
    scan_owned_or_404(db, scan_id, user)
    return _findings_core(db, scan_id)


def _findings_core(db: Session, scan_id: int) -> list:
    """findings() 계산 코어(소유권 검증 제외) — 엔드포인트·워커 요약 공용."""
    _, attempts, finds = _collect(db, scan_id)
    at_by_id = {a.attempt_id: a for a in attempts}
    out = []
    for f in finds:
        at = at_by_id.get(f.attempt_id)
        obj = db.get(Objective, at.objective_id) if at else None
        tech = db.get(AtlasTechnique, obj.atlas_technique_id) if obj else None
        try:
            evidence = json.loads(f.evidence) if f.evidence else {}
        except (ValueError, TypeError):
            evidence = {"raw": f.evidence}
        tech_label = tech.name if tech else (obj.atlas_technique_id if obj else "취약점")
        out.append({
            "findings_id": f.findings_id,
            "objective_id": obj.objective_id if obj else None,   # 프론트 계약
            "title": f"{tech_label} 침투 · {f.severity}",         # 프론트 계약(기법+심각도 파생)
            "severity": f.severity,
            "atlas_technique_id": obj.atlas_technique_id if obj else None,
            "technique_name": tech.name if tech else None,
            "attempt_id": f.attempt_id,
            "generation": at.generation if at else None,
            "prompt": (at.prompt_text[:300] if at else None),
            "evidence": evidence,
            # 완화책은 정본 라이브러리에서 기법별 구조화 가이드로 제공(#79).
            # DB f.mitigation(요약 스냅샷)은 유지되나, 응답은 항상 최신 정본을 반환.
            "mitigation": get_mitigation(obj.atlas_technique_id if obj else None),
            "created_at": f.created_at,
        })
    return out


def _build_summary(scan, rep, finds_detail) -> dict:
    """스캔 결과 요약. 키 없으면 템플릿, ANTHROPIC_API_KEY 있으면 Haiku로 자연어 요약."""
    st = rep["stats"]
    techniques = ", ".join(sorted({f["technique_name"] or f["atlas_technique_id"]
                                   for f in finds_detail})) or "없음"
    template = (
        f"스캔 #{scan.scan_id} 결과: 공격 목표 {rep['total_objectives']}개 중 "
        f"{rep['breached_count']}개가 침투에 성공했습니다"
        f"(커버리지 {rep['coverage_pct']}%, 위험도 {rep['risk_score']}/100). "
        f"총 {st['total_attempts']}회 시도 중 {st['breached_attempts']}회가 방어를 뚫었고, "
        f"취약점 {st['findings']}건이 확인됐습니다. 침투 기법: {techniques}.")

    key = settings.anthropic_api_key
    if not key:
        return {"ai_summary": template, "source": "template"}
    try:
        import anthropic
        from ..observability import trace_llm
        client = anthropic.Anthropic(api_key=key)
        with trace_llm("report-summary", settings.attacker_model,
                       {"scan_id": scan.scan_id, "risk": rep["risk_score"]}) as gen:
            msg = client.messages.create(
                model=settings.attacker_model, max_tokens=400,
                messages=[{"role": "user", "content":
                           "다음 AI 레드팀 스캔 결과를 보안 담당자용으로 3~4문장 한국어로 요약하고 "
                           f"핵심 위험과 권고를 덧붙여줘:\n{template}"}])
            text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
            if gen is not None:
                gen.update(output=text, usage_details={
                    "input_tokens": msg.usage.input_tokens,
                    "output_tokens": msg.usage.output_tokens})
        return {"ai_summary": text or template, "source": "haiku"}
    except Exception:  # noqa: BLE001 - 키 무효/네트워크 등 → 템플릿 폴백(요약은 끊기면 안 됨)
        return {"ai_summary": template, "source": "template-fallback"}



@router.get("/{scan_id}/summary")
def ai_summary(scan_id: int, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    """리포트 AI 요약 — 키 없으면 통계 템플릿, 있으면 Haiku. 소유권 검증(#91). — §5·§7

    캐싱: scan_reports.ai_summary에 한 번 저장 → 이후엔 Haiku 재호출 없이 즉시 반환
    (매 조회마다 Haiku를 부르면 2~5초 지연되어 요약이 뒤늦게 뜸). 스캔이 끝난 상태이고
    실제 Haiku 요약이 나왔을 때만 저장한다(진행 중·템플릿 폴백은 다음에 다시 시도).
    """
    scan = scan_owned_or_404(db, scan_id, user)
    return {"scan_id": scan_id, **warm_summary(db, scan)}


def warm_summary(db: Session, scan) -> dict:
    """요약 캐시 확보(공용: 엔드포인트·워커). 있으면 반환, 없으면 생성 후
    스캔 종료 + Haiku 결과일 때만 scan_reports에 저장한다."""
    row = db.execute(
        sa_select(ScanReport).where(ScanReport.scan_id == scan.scan_id)
    ).scalar_one_or_none()
    if row and row.ai_summary:
        return {"ai_summary": row.ai_summary, "source": "cached"}

    rep = _report_core(db, scan)
    finds = _findings_core(db, scan.scan_id)
    result = _build_summary(scan, rep, finds)

    if scan.status in ("done", "failed", "cancelled") and result.get("source") == "haiku":
        if not row:
            row = ScanReport(scan_id=scan.scan_id)
            db.add(row)
        row.ai_summary = result["ai_summary"]
        row.risk_score = rep["risk_score"]
        row.total_attempts = rep["stats"]["total_attempts"]
        row.breached_attempts = rep["stats"]["breached_attempts"]
        row.findings_count = rep["stats"]["findings"]
        db.commit()
    return result


@router.get("/{scan_id}/code-locations")
def code_locations(scan_id: int, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """스캔에서 테스트한 ATLAS 기법에 해당하는 취약 코드 위치 반환. 소유권 검증(#91)."""
    scan = scan_owned_or_404(db, scan_id, user)
    target = db.get(TargetProject, scan.target_id)
    if not target:
        return []

    objs = db.scalars(sa_select(Objective).where(Objective.scan_id == scan_id)).all()
    tested_atlas_ids = {o.atlas_technique_id for o in objs}

    locs = target.code_locations if isinstance(target.code_locations, list) else []
    return [loc for loc in locs if loc.get("atlas_id") in tested_atlas_ids]
