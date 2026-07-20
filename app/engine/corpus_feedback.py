# -*- coding: utf-8 -*-
"""자기강화: 뚫은 공격을 attack_cases에 되먹임(자가진화 DB). — 로드맵 "데이터베이스 강화"

파이프라인(기본 = 즉시편입):
  스캔 성공(Attempt.breached=True)
    → ①수확 → ②표적특정(카나리·URL·앱이름)·길이 필터 → ③스캔 내 dedup → 기법당 fitness 상위 K
    → ④기존 코퍼스 exact dedup → ⑤적재: source="self_learned", verified=True + 384d 벡터변환
    → 다음 스캔 retrieve가 verified 가중치(+벡터 코사인)로 우선 재사용 = 성공 복리·결과 일관성.

뚫린 건 뚫린 것 — 즉시 편입한다. 오탐/편중은 표적특정 필터 + 기법당 fitness top_k로 거른다.
(promote_hits≥2로 올리면 "재현돼야 편입"하는 묵혀두기 모드: 처음엔 verified=False·embedding=NULL로
 쌓고 같은 프롬프트가 hits회 재뚫림 시 승격. 단 진화가 같은 프롬프트를 잘 재발사 안 해 실제론
 거의 안 쌓임 → 기본은 즉시편입. tags.hits로 재현 횟수는 계속 집계된다.)

안전장치: config 플래그 on/off / source 분리로 한 줄 롤백
(DELETE FROM attack_cases WHERE source='self_learned') / 표적특정 필터+dedup+유형당 상한 /
호출부(tasks.py)의 try/except로 되먹임 실패가 스캔 성공에 무영향.
"""
import logging

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AttackCase, Attempt, Objective, TargetProject
from .embed import embed_query

log = logging.getLogger("redteam.corpus_feedback")

# atlas → 대표 attack_type 역매핑(recon._TYPE_TO_ATLAS는 type→atlas 다대일이라 역은 대표값 하나).
# retrieve 메타필터(atlas 미스 시 attack_type)용 라벨 — 적재 검색은 atlas_technique_id 기준.
_ATLAS_TO_TYPE = {
    "AML.T0054": "jailbreak",
    "AML.T0051.000": "prompt_injection",
    "AML.T0051.001": "indirect_injection",
    "AML.T0056": "system_prompt_leak",
    "AML.T0057": "data_leakage",
    "AML.T0053": "tool_abuse",
    "AML.T0062": "hallucination_induction",
    "AML.T0029": "dos",
}


def _normalize(text: str) -> str:
    """스캔 내 dedup 비교용 정규화: 소문자 + 공백 1칸 축약."""
    return " ".join((text or "").lower().split())


def _target_specific_terms(scan, target) -> list:
    """표적에서만 통하는 프롬프트를 거르기 위한 금칙어(소문자). 카나리·표적 URL 호스트·앱 이름.

    그 표적에서만 통하는 프롬프트(카나리 FLAG 문자열 등)가 일반 코퍼스를 더럽히면 안 되므로,
    금칙어가 들어간 성공 프롬프트는 되먹이지 않는다("일반화되는 기법"만 재사용).
    과잉 매칭(짧고 흔한 토큰) 방지로 4자 미만 텀은 버린다.
    """
    terms = []
    cfg = (target.config or {}) if target else {}
    scfg = (scan.config or {}) if scan else {}
    for c in (cfg.get("canary"), scfg.get("canary")):
        if c:
            terms.append(str(c))
    if target and target.project_name:
        terms.append(str(target.project_name))
    url = cfg.get("url") or (target.repo_url if target else "") or ""
    if url:
        host = url.split("://")[-1].split("/")[0].split(":")[0]  # 스킴·경로·포트 제거
        if host:
            terms.append(host)
    return [t.lower() for t in terms if len(t) >= 4]


def _is_internal_target(target) -> bool:
    """더미/내부 표적(합성 카나리·CI/시연용)은 되먹임하지 않는다 — 테스트가 코퍼스를 오염시키지 않게.

    표적 URL 호스트가 내부(backend/localhost 등)이거나 경로에 /dummy/ 가 있으면 내부로 본다.
    실표적(공개 URL)은 해당 없음.
    """
    cfg = (target.config or {}) if target else {}
    url = (cfg.get("url") or (target.repo_url if target else "") or "").lower()
    if not url:
        return False
    host = url.split("://")[-1].split("/")[0].split(":")[0]
    if host in ("backend", "localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"):
        return True
    return "/dummy/" in url


def harvest_successful_attacks(db: Session, scan) -> dict:
    """이 스캔의 breach된 시도를 필터·dedup해 staging 적재/승격한다.

    반환: {"staged": 신규 후보 수, "promoted": 이번에 verified 승격된 수, "rehit": 재현 갱신 수}.
    플래그 OFF거나 되먹일 게 없으면 전부 0. (호출부에서 try/except로 감싼다)
    """
    zero = {"staged": 0, "promoted": 0, "rehit": 0}
    if not settings.corpus_feedback_enabled:
        return zero

    # 더미/내부 표적(CI·시연용 합성 카나리)은 되먹이지 않는다 — 테스트가 코퍼스를 오염시키지 않게.
    target = db.get(TargetProject, scan.target_id)
    if _is_internal_target(target):
        log.info("자기강화 skip(내부/더미 표적 scan=%s)", scan.scan_id)
        return zero

    # ── ① 수확: 이 스캔의 breach된 시도 + 목표 atlas ──
    rows = (db.query(Attempt.prompt_text, Attempt.fitness, Objective.atlas_technique_id)
              .join(Objective, Attempt.objective_id == Objective.objective_id)
              .filter(Objective.scan_id == scan.scan_id, Attempt.breached.is_(True))
              .all())
    if not rows:
        return zero

    blocked = _target_specific_terms(scan, target)
    min_len = settings.corpus_feedback_min_len

    # ── ② 필터(표적특정·길이) + ③ 스캔 내 dedup → 기법당 후보 모음 ──
    seen = set()                    # 스캔 내 정규화 중복 제거(한 프롬프트는 한 유형에만)
    cand = {}                       # atlas_id -> list[(fitness, prompt)]
    for prompt, fitness, atlas_id in rows:
        p = (prompt or "").strip()
        if len(p) < min_len:
            continue
        low = p.lower()
        if any(t in low for t in blocked):     # 표적특정 → 일반화 안 됨, 버림
            continue
        norm = _normalize(p)
        if norm in seen:
            continue
        seen.add(norm)
        cand.setdefault(atlas_id, []).append((float(fitness or 0.0), p))
    if not cand:
        return zero

    # 기법당 fitness 상위 K만 남김(폭증 차단)
    top_k = settings.corpus_feedback_top_k
    picked = []                     # (atlas_id, fitness, prompt)
    for atlas_id, lst in cand.items():
        lst.sort(key=lambda t: t[0], reverse=True)
        for fitness, p in lst[:top_k]:
            picked.append((atlas_id, fitness, p))
    if not picked:
        return zero

    # ── 기존 attack_cases 조회(후보 원문으로만 좁힘 — 21k 전체를 안 퍼올림) ──
    # self_learned 행 = 우리 staging(재현 갱신 대상). 그 외 source = 이미 원본 코퍼스에 있음(skip).
    # 매칭은 정규화(대소문자·공백 무시) 키로 — 대소문자만 다른 변형이 중복 적재/hits 분산되지 않게.
    # SQL은 lower()로 1차 좁히고(공백까지 맞추는 별도 컬럼은 오버스펙), 파이썬에서 _normalize로 확정.
    picked_prompts = list({p for _, _, p in picked})
    lowered = list({p.lower() for p in picked_prompts})
    existing = db.query(AttackCase).filter(func.lower(AttackCase.prompt_text).in_(lowered)).all()
    staged_rows = {}                # normalized -> AttackCase(self_learned)
    seed_norms = set()              # 원본 코퍼스에 이미 있는 정규화 원문
    for r in existing:
        n = _normalize(r.prompt_text)
        if r.source == "self_learned":
            staged_rows.setdefault(n, r)
        else:
            seed_norms.add(n)

    promote_hits = settings.corpus_feedback_promote_hits
    staged = promoted = rehit = 0

    # ── ④⑤ staging 적재 / 재현 갱신 / 승격(벡터변환) ──
    for atlas_id, fitness, p in picked:
        norm = _normalize(p)
        if norm in seed_norms:                      # 이미 원본 코퍼스 → 되먹이지 않음
            continue
        row = staged_rows.get(norm)
        if row is None:
            # 신규 후보: staging(verified=False, embedding=NULL). promote_hits=1이면 즉시 승격.
            verified_now = promote_hits <= 1
            db.add(AttackCase(
                prompt_text=p,
                attack_type=_ATLAS_TO_TYPE.get(atlas_id, "jailbreak"),
                atlas_technique_id=atlas_id,
                source="self_learned",
                verified=verified_now,
                tags={"hits": 1, "scan_id": scan.scan_id, "target_id": scan.target_id,
                      "fitness": round(fitness, 4)},
                embedding=embed_query(p) if verified_now else None))
            if verified_now:
                promoted += 1
            else:
                staged += 1
            seed_norms.add(norm)                    # 같은 배치 내 재삽입 방지
        else:
            # 재현: hits += 1 → 임계 도달 시 벡터변환 + verified 승격
            tags = dict(row.tags or {})
            hits = int(tags.get("hits", 1)) + 1
            tags["hits"] = hits
            tags["last_scan_id"] = scan.scan_id
            row.tags = tags                         # JSON 컬럼은 재대입해야 변경 감지됨
            rehit += 1
            if not row.verified and hits >= promote_hits:
                if row.embedding is None:
                    row.embedding = embed_query(p)  # 승격 시점에만 벡터변환
                row.verified = True
                promoted += 1

    if staged or promoted or rehit:
        db.commit()
        log.info("자기강화(scan=%s): staged=%d promoted=%d rehit=%d",
                 scan.scan_id, staged, promoted, rehit)
    return {"staged": staged, "promoted": promoted, "rehit": rehit}
