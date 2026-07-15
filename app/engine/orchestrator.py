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
from ..mitigations import get_mitigation
from ..models import Attempt, Finding
from .actor import make_actor
from .judge import judge
from .mutators import mutate, pick_op
from .retrieve import retrieve_seeds
from .scan_manager import publish
from .select import Node, select

ELITISM_ALPHA = 4        # 상위 α개 무변형 생존(AutoDAN)
STAGNATION_LIMIT = 2     # 개선 없는 세대 연속 한계 → 조기 종료


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

    def _record_attempt(prompt, resp, v, generation, parent_id, op):
        at = Attempt(
            objective_id=objective.objective_id, parent_id=parent_id,
            prompt_text=prompt, response_text=resp, fitness=v["score"],
            generation=generation, mutation_op=op or "",
            breached=(v["verdict"] == "breach"))
        db.add(at)
        db.commit()
        db.refresh(at)
        metrics.ATTEMPTS.labels(verdict=v["verdict"]).inc()             # 시도(판정별) (#93)
        metrics.ATTEMPT_FITNESS.observe(v["score"])                     # fitness 분포
        metrics.JUDGE_STAGE.labels(stage=v.get("stage", "unknown")).inc()  # 판정 계층
        payload = {
            "attempt_id": at.attempt_id, "generation": generation,
            "parent_id": parent_id, "verdict": v["verdict"], "score": v["score"],
            "mutation_op": op or "seed", "atlas": atlas_id,
            "prompt": prompt[:200]}
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
    seeds = retrieve_seeds(db, atlas_id=atlas_id, k=cfg.population_size)
    population: list = []
    best = 0.0
    for seed in seeds:
        resp = _fire(actor, seed.prompt_text)
        v = judge(resp, canary)
        at = _record_attempt(seed.prompt_text, resp, v, 0, None, None)
        best = max(best, v["score"])
        if v["verdict"] == "breach":
            _record_finding(at, v)
            return True
        population.append(Node(at.attempt_id, seed.prompt_text, v["score"]))

    # ── 진화 세대: select(UCB) → mutate → fire → judge → elitism ──
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
        op = pick_op()
        child, _improvement = mutate(parent.prompt, op, [n.prompt for n in population])
        resp = _fire(actor, child)
        v = judge(resp, canary)
        at = _record_attempt(child, resp, v, gen, parent.attempt_id, op)

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
