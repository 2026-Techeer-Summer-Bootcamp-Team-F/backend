# -*- coding: utf-8 -*-
"""§5 Results — 리포트·히트맵·Findings·AI요약. (담당: 엔진/결과) — API-명세.md §5

전부 읽기 전용 집계 쿼리(scans/objectives/attempts/findings 조인). 결과 = 대시보드 원본.
AI 요약은 키 없으면 템플릿, ANTHROPIC_API_KEY 있으면 Haiku로 자동 업그레이드(#40·#42).
"""
import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import Attempt, AtlasTechnique, Finding, Objective, Scan

router = APIRouter(prefix="/scans", tags=["results"])

_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 5}


def _scan_or_404(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "스캔 없음")
    return scan


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
def report(scan_id: int, db: Session = Depends(get_db)):
    """대시보드 통계: 목표/시도/침투/취약점 + 위험도(심각도 가중). — §5"""
    scan = _scan_or_404(db, scan_id)
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
def heatmap(scan_id: int, db: Session = Depends(get_db)):
    """ATLAS 기법별 침투 히트맵 — objective별 상태 + 최고 fitness. — §5"""
    _scan_or_404(db, scan_id)
    objs, attempts, _ = _collect(db, scan_id)
    # objective별 최고 fitness
    best: dict = {}
    for a in attempts:
        best[a.objective_id] = max(best.get(a.objective_id, 0.0), a.fitness or 0.0)
    cells = []
    for o in objs:
        tech = db.get(AtlasTechnique, o.atlas_technique_id)
        cells.append({
            "atlas_technique_id": o.atlas_technique_id,
            "name": tech.name if tech else o.atlas_technique_id,
            "tactic": tech.tactic if tech else "",
            "status": o.status,
            "breached": o.status == "breached",
            "best_score": round(best.get(o.objective_id, 0.0), 3),
        })
    return {"scan_id": scan_id, "cells": cells}


@router.get("/{scan_id}/findings")
def findings(scan_id: int, db: Session = Depends(get_db)):
    """취약점 목록 + 증거 + 완화책(finding→attempt→objective→atlas 조인). — §5"""
    _scan_or_404(db, scan_id)
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
        out.append({
            "findings_id": f.findings_id,
            "severity": f.severity,
            "atlas_technique_id": obj.atlas_technique_id if obj else None,
            "technique_name": tech.name if tech else None,
            "attempt_id": f.attempt_id,
            "generation": at.generation if at else None,
            "prompt": (at.prompt_text[:300] if at else None),
            "evidence": evidence,
            "mitigation": f.mitigation,
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
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model=settings.attacker_model, max_tokens=400,
            messages=[{"role": "user", "content":
                       "다음 AI 레드팀 스캔 결과를 보안 담당자용으로 3~4문장 한국어로 요약하고 "
                       f"핵심 위험과 권고를 덧붙여줘:\n{template}"}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        return {"ai_summary": text or template, "source": "haiku"}
    except Exception:  # noqa: BLE001 - 키 무효/네트워크 등 → 템플릿 폴백(요약은 끊기면 안 됨)
        return {"ai_summary": template, "source": "template-fallback"}


@router.get("/{scan_id}/summary")
def ai_summary(scan_id: int, db: Session = Depends(get_db)):
    """리포트 AI 요약 — 키 없으면 통계 템플릿, 있으면 Haiku. — §5·§7"""
    scan = _scan_or_404(db, scan_id)
    rep = report(scan_id, db)
    finds = findings(scan_id, db)
    return {"scan_id": scan_id, **_build_summary(scan, rep, finds)}
