# -*- coding: utf-8 -*-
"""진화 루프 메인 (엔진 심장). — ARCHITECTURE.md §4, 기획 §5.4

retrieve → (0세대 씨앗 발사) → [select(UCB) → mutate → fire → judge → update(elitism)] → 종료.
GPTFuzzer 뼈대 + AutoDAN elitism + UCB 씨앗선택(오픈소스-분석 §6.2). 변이는 결정론(AI 0원).
종료조건(기획 §5.4): 성공(breach) / 예산(max_generations) / 정체(stagnation) / 전멸(extinct).

동작 컨텍스트: Celery 워커(동기)에서 호출. 액터 send는 async(httpx) → asyncio.run으로 감싼다.
스키마: 린 모델에 매핑 — Attempt.fitness=judge score, Attempt.breached=(verdict==breach).
"""
import asyncio
import json
import time
from dataclasses import dataclass

from .. import metrics
from ..config import settings
from ..mitigations import get_mitigation
from ..models import AtlasTechnique, Attempt, Finding
from .actor import make_actor
from .attacker import next_attack
from .judge import judge
from .mutators import mutate, pick_op
from .retrieve import retrieve_seeds
from .scan_manager import publish
from .select import Node, select

ELITISM_ALPHA = 4        # 상위 α개 무변형 생존(AutoDAN)
STAGNATION_LIMIT = 2     # 개선 없는 세대 연속 한계 → 조기 종료
EVENT_TEXT_CAP = 4000    # 이벤트에 싣는 공격/응답 전문 상한(#97)


def _cap(text) -> tuple:
    """이벤트용 텍스트를 EVENT_TEXT_CAP로 자른다. (자른 텍스트, 잘렸는지) 반환. — #97

    전문은 attempts 테이블에 이미 저장되므로 scan_events.payload(JSON)까지 무제한으로
    실으면 시도마다 DB가 두 배로 분다. 캡으로 페이로드 크기를 묶는다.
    """
    s = text or ""
    if len(s) <= EVENT_TEXT_CAP:
        return s, False
    return s[:EVENT_TEXT_CAP], True


@dataclass
class EvolveConfig:
    population_size: int = 8
    max_generations: int = 6


def _fire(actor, prompt: str) -> str:
    """async 액터 send를 동기 워커에서 실행(발사 1회 = 독립 이벤트루프)."""
    t0 = time.monotonic()
    try:
        return asyncio.run(actor.send(prompt))
    finally:
        metrics.ACTOR_LATENCY.observe(time.monotonic() - t0)   # 표적 응답지연(#93)


def run_evolution(db, scan_id: int, objective, target, canary,
                  cfg: EvolveConfig = EvolveConfig()) -> bool:
    """objective 1개에 대한 진화 루프. 뚫으면 True(+Finding 기록), 아니면 False.

    - canary: 성공 판정용 FLAG 문자열(target/scan config에서 옴). judge에 전달.
    - 모든 시도는 Attempt로 기록되고 scan_events(폴링 SSE)로 중계된다.
    """
    actor = make_actor(target)
    atlas_id = objective.atlas_technique_id
    # 기법명은 목표당 1회만 조회(시도마다 조회하면 N+1). 마스터에 없으면 ""(프론트가 코드로 폴백).
    technique = db.get(AtlasTechnique, atlas_id)
    atlas_name = technique.name if technique else ""
    attempt_index = 0

    # 표적 프로필(judge/retrieve/attacker 공용) — 정찰정보. None 방어적 처리. — #130
    profile = {
        "model": target.model or "",
        "system_prompt": target.system_prompt or "",
        "tools": (target.tools or {}).get("detected", []),
        "defenses": (target.defences or {}).get("detected", []),
        "rag_sources": (target.rag_sources or {}).get("detected", []),
    }

    def _publish_started(prompt, generation, op, improvement=None):
        """발사 직전: 공격 프롬프트만 실어 발행 → 채팅이 공격 말풍선+타이핑을 그린다. — #102

        순번(attempt_index)을 여기서 확정한다(발사 시점). 뒤따르는 attempt가 같은
        (objective_id, attempt_index)로 나가므로 프론트가 짝을 맞춰 응답·판정을 채운다.
        attempt_id는 아직 DB 행이 없어 실을 수 없어 상관 키로 쓰지 않는다.
        """
        nonlocal attempt_index
        attempt_index += 1
        attack_prompt, prompt_truncated = _cap(prompt)
        publish(scan_id, "attempt_started", {
            "attempt_index": attempt_index, "generation": generation,
            "mutation_op": op or "seed", "improvement": improvement or "",
            "attack_prompt": attack_prompt, "attack_prompt_truncated": prompt_truncated,
            "atlas": atlas_id, "atlas_name": atlas_name},
            db=db, objective_id=objective.objective_id)

    def _record_attempt(prompt, resp, v, generation, parent_id, op, improvement=None):
        at = Attempt(
            objective_id=objective.objective_id, parent_id=parent_id,
            prompt_text=prompt, response_text=resp, fitness=v["score"],
            generation=generation, mutation_op=op or "",
            improvement=improvement or "",
            breached=(v["verdict"] == "breach"))
        db.add(at)
        db.commit()
        db.refresh(at)
        metrics.ATTEMPTS.labels(verdict=v["verdict"]).inc()             # 시도(판정별) (#93)
        metrics.ATTEMPT_FITNESS.observe(v["score"])                     # fitness 분포
        metrics.JUDGE_STAGE.labels(stage=v.get("stage", "unknown")).inc()  # 판정 계층
        # 순번은 _publish_started가 발사 시점에 확정 → 여기선 읽기만(같은 값이라 짝이 맞음).
        attack_prompt, prompt_truncated = _cap(prompt)
        target_response, response_truncated = _cap(resp)
        payload = {
            "attempt_id": at.attempt_id, "generation": generation,
            "parent_id": parent_id, "verdict": v["verdict"], "score": v["score"],
            "mutation_op": op or "seed", "improvement": improvement or "", "atlas": atlas_id,
            "prompt": prompt[:200],
            # 실시간 공격 채팅(#97): 공격/응답 전문 + 판정 근거. 모든 attempt에 항상 실어
            # 프론트에 undefined 분기가 없게 한다. verdict는 breach|safe|error 그대로 두고
            # 방어/돌파 표현은 프론트가 매핑(기존 소비자 하위호환).
            "attack_prompt": attack_prompt, "attack_prompt_truncated": prompt_truncated,
            "target_response": target_response, "target_response_truncated": response_truncated,
            "canary_triggered": bool(v.get("canary_hit")),
            "flag_token": v.get("canary_hit"),
            "attempt_index": attempt_index, "atlas_name": atlas_name}
        if v["verdict"] == "error":
            payload["error"] = resp[:200]
        publish(scan_id, "attempt", payload, db=db, objective_id=objective.objective_id)
        return at

    def _record_finding(at, v):
        evidence = json.dumps({
            "prompt": at.prompt_text, "response": at.response_text,
            "canary_hit": v.get("canary_hit"), "stage": v.get("stage")},
            ensure_ascii=False)
        db.add(Finding(
            attempt_id=at.attempt_id,
            severity="critical" if v.get("canary_hit") else "high",
            evidence=evidence,
            # 완화 스냅샷 = 정본 라이브러리 요약(응답은 results.py가 전체 구조화 반환, #79)
            mitigation=get_mitigation(atlas_id)["summary"]))
        objective.status = "breached"
        db.commit()
        metrics.BREACHES.labels(atlas=atlas_id or "unknown").inc()   # 침투(기법별) (#93)
        publish(scan_id, "finding", {
            "attempt_id": at.attempt_id, "atlas": atlas_id,
            "severity": "critical" if v.get("canary_hit") else "high",
            "canary_hit": v.get("canary_hit")},
            db=db, objective_id=objective.objective_id)

    # ── 0세대: 씨앗 그대로 발사 (LLM 안 씀 = 쌈) ──
    # 정찰정보로 의미검색 질의 구성(RETRIEVE_VECTOR_ENABLED off면 retrieve가 무시 → 기존과 동일).
    query_text = " ".join(
        x for x in [atlas_name, profile["system_prompt"][:300], " ".join(profile["tools"])] if x
    )[:1000]
    seeds = retrieve_seeds(db, atlas_id=atlas_id, k=cfg.population_size, query_text=query_text)
    # commit 전에 prompt_text를 문자열로 미리 추출 — publish의 db.commit()이 ORM 객체를 expire시켜
    # 이후 루프에서 lazy reload가 필요해지는 문제 방지.
    seed_texts = [(s.prompt_text or "") for s in seeds]
    publish(scan_id, "seeds_retrieved", {
        "atlas": atlas_id, "atlas_name": atlas_name,
        "count": len(seed_texts),
        "previews": [t[:80] for t in seed_texts],
    }, db=db, objective_id=objective.objective_id)
    population: list = []
    best = 0.0
    history: list = []   # 이 objective의 시도 히스토리(공격자 AI few-shot용) — #130
    for seed_text in seed_texts:
        _publish_started(seed_text, 0, None)      # 발사 직전 = 채팅 공격 말풍선(#102)
        resp = _fire(actor, seed_text)
        v = judge(resp, canary, system_prompt=profile["system_prompt"], objective=atlas_name)
        at = _record_attempt(seed_text, resp, v, 0, None, None)
        history.append({"prompt": seed_text, "response": resp,
                        "verdict": v["verdict"], "score": v["score"]})
        best = max(best, v["score"])
        if v["verdict"] == "breach":
            _record_finding(at, v)
            return True
        population.append(Node(at.attempt_id, seed_text, v["score"]))

    # ── 진화 세대: select(UCB) → mutate/attacker → fire → judge → elitism ──
    stagnation = 0
    step = 0
    for gen in range(1, cfg.max_generations + 1):
        publish(scan_id, "progress", {
            "phase": "evolve", "generation": gen, "best_score": round(best, 3),
            "population": len(population)}, db=db, objective_id=objective.objective_id)
        if not population:
            objective.status = "exhausted"
            db.commit()
            return False

        step += 1
        parent = select(population, step)
        if settings.attacker_ai_enabled:
            # 세대마다 코퍼스 재검색(재검색): 현재 best 공격 + 직전 응답 기준으로 관련 씨앗을 다시
            # 뽑아 공격자 예시로 준다(벡터 off면 retrieve가 메타필터로 폴백). 실패 시 0세대 seeds 재사용.
            gen_query = " ".join(
                x for x in [atlas_name, parent.prompt[:300],
                            (history[-1]["response"] if history else "")[:300]] if x)[:1000]
            gen_seeds = retrieve_seeds(db, atlas_id=atlas_id, k=cfg.population_size,
                                       query_text=gen_query) or seeds
            # AI 공격자: 목표+프로필+히스토리+(재검색)씨앗 보고 다음 한 수 설계.
            #   → 새 공격 생성(변형) 또는 재검색된 검증 씨앗 활용. 거부/실패 시 내부 결정론 폴백. — #130
            atk = next_attack(atlas_id, atlas_name, profile, history, gen_seeds, parent.prompt,
                              [n.prompt for n in population])
            child, op, improvement = atk["prompt"], atk["technique"], atk["improvement"]
        else:
            op = pick_op()
            child, improvement = mutate(parent.prompt, op, [n.prompt for n in population])
        _publish_started(child, gen, op, improvement)      # 발사 직전 = 채팅 공격 말풍선(#102)
        resp = _fire(actor, child)
        v = judge(resp, canary, system_prompt=profile["system_prompt"], objective=atlas_name)
        at = _record_attempt(child, resp, v, gen, parent.attempt_id, op, improvement)
        history.append({"prompt": child, "response": resp,
                        "verdict": v["verdict"], "score": v["score"]})

        # UCB 역전파(부모가 좋은 자식을 냈으면 보상↑)
        parent.visits += 1
        parent.reward += v["score"]

        if v["verdict"] == "breach":
            _record_finding(at, v)
            return True

        # add_if_improved + elitism (상위 α 생존)
        if not population or v["score"] >= min(n.score for n in population):
            population.append(Node(at.attempt_id, child, v["score"]))
            population.sort(key=lambda n: n.score, reverse=True)
            del population[ELITISM_ALPHA:]

        if v["score"] > best + 1e-6:
            best = v["score"]
            stagnation = 0
        else:
            stagnation += 1
        db.commit()

        if stagnation >= STAGNATION_LIMIT and gen >= 2:
            objective.status = "safe"
            db.commit()
            return False

    if objective.status == "pending" or objective.status == "running":
        objective.status = "safe"
        db.commit()
    return False
