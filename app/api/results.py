# -*- coding: utf-8 -*-
"""§5 Results — 리포트·히트맵·Findings·AI요약. (담당: 엔진/결과) — API-명세.md §5

전부 읽기 전용 집계 쿼리(scans/objectives/attempts/findings 조인). 결과 = 대시보드 원본.
AI 요약은 키 없으면 템플릿, ANTHROPIC_API_KEY 있으면 Haiku로 자동 업그레이드(#40·#42).
"""
import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select as sa_select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..authz import scan_owned_or_404
from ..config import settings
from ..db import get_db
from ..deps import get_current_user
from ..mitigations import get_mitigation
from ..models import (Attempt, AtlasTechnique, Finding, Objective, Scan,
                      ScanReport, TargetProject, User)
from ..recon import fetch_commit_diff
from ..security import decrypt_token

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


# objective status → 버전비교용 3분류. _heat_status와 같은 의미(미확정은 방어로 세지 않음).
_STATUS_RANK = {"breached": 2, "defended": 1, "untested": 0}


def _obj_class(status: str) -> str:
    """objective status → 'breached' | 'defended' | 'untested'.

    pending/running은 아직 확정 안 됨(untested) → '방어 성공'으로 오집계하지 않는다.
    그 외 종료 상태(safe/exhausted/failed)는 방어(defended).
    """
    if status == "breached":
        return "breached"
    if status in ("pending", "running"):
        return "untested"
    return "defended"


def _technique_status(db: Session, scan_id: int) -> dict:
    """스캔의 ATLAS 기법별 판정 요약 → {atlas_id: {name, status, score}} — 버전비교용(#132).

    status: 'breached'|'defended'|'untested'. score: 그 기법 시도 최고 fitness.
    같은 기법이 여러 objective로 잡히면 위험한 쪽(breached>defended>untested)으로 합친다.
    """
    objs, attempts, _ = _collect(db, scan_id)
    best: dict = {}                                   # objective_id -> 최고 fitness
    for a in attempts:
        best[a.objective_id] = max(best.get(a.objective_id, 0.0), a.fitness or 0.0)
    out: dict = {}
    for o in objs:
        score = round(best.get(o.objective_id, 0.0), 3)
        cls = _obj_class(o.status)
        cur = out.get(o.atlas_technique_id)
        if cur is None:
            tech = db.get(AtlasTechnique, o.atlas_technique_id)
            out[o.atlas_technique_id] = {
                "name": tech.name if tech else o.atlas_technique_id,
                "status": cls, "score": score,
            }
        else:
            if _STATUS_RANK[cls] > _STATUS_RANK[cur["status"]]:
                cur["status"] = cls
            cur["score"] = max(cur["score"], score)
    return out


def _verdict(before_status: str, after_status: str) -> str:
    """이전→현재 판정 변화 → verdict(#132). before/after는 breached|defended만 들어온다."""
    if before_status == "breached":
        return "solved" if after_status == "defended" else "open"
    # before == defended
    return "regressed" if after_status == "breached" else "keep"


def compare_techniques(db: Session, base_scan_id: int | None, cur_scan_id: int) -> list:
    """두 스캔의 기법별 판정 변화 목록(#132). base 없으면(=baseline) 빈 리스트.

    현재 스캔이 확정한(breached|defended) 기법을 기준으로 이전 판정과 비교한다.
    - 현재 미확정(untested) 기법은 비교 불가라 제외한다.
    - 이전에 없거나 미확정이면 before=null, verdict='keep'(비교 기준 없음).
    """
    if base_scan_id is None:
        return []
    prev = _technique_status(db, base_scan_id)
    cur = _technique_status(db, cur_scan_id)
    out = []
    for atlas_id, c in cur.items():
        if c["status"] == "untested":          # 현재 스캔에서 미확정 → 판정 변화 계산 불가
            continue
        p = prev.get(atlas_id)
        if p and p["status"] == "untested":    # 이전이 미확정이면 비교 기준으로 못 씀
            p = None
        before = {"status": p["status"], "score": p["score"]} if p else None
        verdict = _verdict(p["status"], c["status"]) if p else "keep"
        out.append({
            "atlas_technique_id": atlas_id,
            "name": c["name"],
            "before": before,
            "after": {"status": c["status"], "score": c["score"]},
            "verdict": verdict,
        })
    # 판정 우선순위: 해결/후퇴/미해결을 위로(사용자가 변화부터 보게), 유지는 아래로.
    order = {"solved": 0, "regressed": 1, "open": 2, "keep": 3}
    out.sort(key=lambda r: order.get(r["verdict"], 9))
    return out


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



class DescribePromptRequest(BaseModel):
    prompt: str


@router.post("/describe-prompt")
def describe_prompt_endpoint(req: DescribePromptRequest, user: User = Depends(get_current_user)):
    """단일 프롬프트 유형 설명 — Haiku로 어떤 공격인지 20자 이내 한 줄 설명. 키 없으면 빈 문자열."""
    key = settings.anthropic_api_key
    if not key or not req.prompt.strip():
        return {"description": ""}
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model=settings.attacker_model, max_tokens=60,
            messages=[{"role": "user", "content":
                       f"다음 AI 공격 프롬프트를 보고 어떤 유형의 공격인지 "
                       f"20자 이내 한국어로 설명해줘. 설명만 출력(따옴표·마침표 없이):\n{req.prompt[:300]}"}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        return {"description": text.strip()}
    except Exception:  # noqa: BLE001
        return {"description": ""}


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
        try:
            db.commit()
        except IntegrityError:
            # 워커(스캔종료 사전생성)와 엔드포인트(/summary 조회)가 거의 동시에 같은
            # scan_reports 행을 INSERT하면 UNIQUE(scan_id) 충돌 → 롤백 후 이미 저장된
            # 행을 읽어 반환(레이스 방어, 500 방지). 상대가 방금 저장한 요약을 그대로 씀.
            db.rollback()
            existing = db.execute(
                sa_select(ScanReport).where(ScanReport.scan_id == scan.scan_id)
            ).scalar_one_or_none()
            if existing and existing.ai_summary:
                return {"ai_summary": existing.ai_summary, "source": "cached"}
    return result


@router.get("/{scan_id}/evolution")
def evolution(scan_id: int, atlas_id: str, db: Session = Depends(get_db),
              user: User = Depends(get_current_user)):
    """기법별 진화 트리 데이터 — attempt 계보(parent_id 체인). 소유권 검증."""
    scan_owned_or_404(db, scan_id, user)
    objs = db.scalars(
        sa_select(Objective).where(
            Objective.scan_id == scan_id,
            Objective.atlas_technique_id == atlas_id,
        )
    ).all()
    if not objs:
        return {"atlas_id": atlas_id, "nodes": []}
    obj_ids = [o.objective_id for o in objs]
    attempts = db.scalars(
        sa_select(Attempt).where(Attempt.objective_id.in_(obj_ids))
        .order_by(Attempt.generation, Attempt.attempt_id)
    ).all()
    nodes = []
    for a in attempts:
        nodes.append({
            "attempt_id": a.attempt_id,
            "parent_id": a.parent_id,
            "generation": a.generation,
            "prompt_preview": (a.prompt_text or "")[:120],
            "score": round(a.fitness or 0.0, 3),
            "verdict": "breached" if a.breached else "safe",
            "mutation_op": a.mutation_op or "seed",
            "improvement": a.improvement or "",
        })
    return {"atlas_id": atlas_id, "nodes": nodes}


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


@router.get("/{scan_id}/version-diff")
def version_diff(scan_id: int, base: int | None = None,
                 db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    """스캔 버전 비교(#132) — 이전↔현재 코드 diff + 기법별 판정 변화. 소유권 검증(#91).

    base 생략 시 같은 표적의 직전 스캔을 자동 선택. 이전 스캔이 없으면 baseline(빈 상태).
    코드 diff는 두 스캔의 commit_sha로 GitHub compare API를 호출해 얻고, 실패해도
    기법별 판정 변화(results)는 항상 반환한다(diff_error로 사유 안내).
    """
    cur = scan_owned_or_404(db, scan_id, user)
    # base 결정: 명시되면 검증(본인·같은 표적), 아니면 직전 스캔 자동.
    if base is not None:
        base_scan = scan_owned_or_404(db, base, user)
        if base_scan.target_id != cur.target_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "다른 표적의 스캔과는 비교할 수 없습니다")
    else:
        # 직전 '완료(done)' 스캔만 자동 기준으로. 실행중/실패 스캔이 base가 되면
        # objective가 미확정이라 verdict가 잘못 나오므로 제외(CodeRabbit #134).
        base_scan = db.scalars(
            sa_select(Scan)
            .where(Scan.target_id == cur.target_id, Scan.scan_id < scan_id,
                   Scan.status == "done")
            .order_by(Scan.scan_id.desc()).limit(1)).first()

    base_scan_id = base_scan.scan_id if base_scan else None
    baseline = base_scan is None
    head_sha = cur.commit_sha
    base_sha = base_scan.commit_sha if base_scan else None

    results = compare_techniques(db, base_scan_id, scan_id)

    files: list = []
    diff_error = None
    if baseline:
        diff_error = "최초 스캔이라 비교할 이전 버전이 없습니다."
    elif not base_sha or not head_sha:
        diff_error = "커밋 정보가 없어 코드 변경점을 가져올 수 없습니다."
    else:
        target = db.get(TargetProject, cur.target_id)
        token = ""
        try:
            owner = db.get(User, target.user_id) if target else None
            if owner and owner.access_token_enc:
                token = decrypt_token(owner.access_token_enc) or ""
        except Exception:  # noqa: BLE001 - 토큰 복호화 실패 → 토큰 없이(공개 레포) 시도
            token = ""
        files = fetch_commit_diff(
            target.repo_url if target else "", base_sha, head_sha, token)
        if not files:
            diff_error = "변경된 파일이 없거나 diff를 가져오지 못했습니다."

    resp = {
        "scan_id": scan_id, "base_scan_id": base_scan_id,
        "head_sha": head_sha, "base_sha": base_sha,
        "baseline": baseline, "results": results, "files": files,
    }
    if diff_error:
        resp["diff_error"] = diff_error
    return resp
