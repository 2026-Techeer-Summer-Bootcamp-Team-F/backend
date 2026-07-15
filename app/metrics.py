# -*- coding: utf-8 -*-
"""스캔 고유 Prometheus 메트릭 — 관측성 대시보드의 알맹이. (#93) — ARCHITECTURE.md §3.11

기본 /metrics(prometheus-fastapi-instrumentator)는 HTTP 요청수·지연만 준다.
"우리 도구가 실제로 뭘 하는지"(발사한 공격·침투·판정계층·표적 응답지연)는 여기서 정의한다.

⚠️ 이 카운터들은 대부분 **워커(Celery) 프로세스**에서 증가한다(진화 루프가 거기서 돎).
   → 워커가 자체 /metrics HTTP 서버를 띄우고(celery_app worker_process_init) Prometheus가
     워커도 긁는다. backend(웹) 프로세스에도 같은 이름이 등록되나 대부분 0으로 남는다.
   Grafana 쿼리는 sum(...)으로 job(backend/worker) 구분 없이 합산하므로 무해.

prometheus_client 미설치(로컬 최소구성)에서도 앱이 죽지 않게 no-op 스텁으로 폴백한다.
"""

try:
    from prometheus_client import Counter, Gauge, Histogram

    SCAN_STARTED = Counter(
        "redteam_scans_started_total", "워커가 실행 시작한 스캔 수")
    SCAN_FINISHED = Counter(
        "redteam_scans_finished_total", "종료된 스캔 수", ["status"])  # done/failed/cancelled
    SCAN_DURATION = Histogram(
        "redteam_scan_duration_seconds", "스캔 1건 소요(초)",
        buckets=(5, 15, 30, 60, 120, 180, 300, 600))
    SCANS_IN_PROGRESS = Gauge(
        "redteam_scans_in_progress", "현재 진행 중인 스캔 수")

    ATTEMPTS = Counter(
        "redteam_attempts_total", "발사한 공격 시도 수", ["verdict"])  # breach/safe/error
    BREACHES = Counter(
        "redteam_breaches_total", "침투(뚫림) 수", ["atlas"])
    ATTEMPT_FITNESS = Histogram(
        "redteam_attempt_fitness", "attempt fitness(판정 점수) 분포",
        buckets=(0.1, 0.2, 0.3, 0.5, 0.7, 0.85, 0.9, 1.0))

    ACTOR_LATENCY = Histogram(
        "redteam_actor_send_seconds", "표적 앱(LLM) 1회 호출 지연(초)",
        buckets=(0.25, 0.5, 1, 2, 5, 10, 20, 30, 60))
    JUDGE_STAGE = Counter(
        "redteam_judge_stage_total", "판정을 확정한 계층 분포",
        ["stage"])  # canary/rule/heuristic/haiku/actor

    ENABLED = True

except ImportError:  # 로컬 최소구성 — 메트릭은 조용히 no-op
    class _Noop:
        def labels(self, *a, **k):
            return self

        def inc(self, *a, **k):
            pass

        def observe(self, *a, **k):
            pass

        def set(self, *a, **k):
            pass

        def dec(self, *a, **k):
            pass

    SCAN_STARTED = SCAN_FINISHED = SCAN_DURATION = SCANS_IN_PROGRESS = _Noop()
    ATTEMPTS = BREACHES = ATTEMPT_FITNESS = ACTOR_LATENCY = JUDGE_STAGE = _Noop()
    ENABLED = False
