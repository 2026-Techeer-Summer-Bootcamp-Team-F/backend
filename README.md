# AI 레드팀 — Backend

AI 챗봇/에이전트 앱 자동 모의해킹 도구의 백엔드. **검증 공격 코퍼스 벡터검색 + 진화형 공격**이 차별점.
스택: FastAPI + Celery + Redis + PostgreSQL(pgvector). 상세: `docs/ARCHITECTURE.md`.

## 실행

```bash
# A. 도커(권장) — db(pgvector)+redis+api 한번에
cp .env.example .env            # 값은 기본으로 OK(mock)
docker compose up --build       # → http://localhost:8000/health

# B. 로컬 단독 (파이썬 3.11+; 로컬 homebrew pip 깨졌으면 도커 쓰기)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload   # sqlite 기본
```

## 디렉토리 (ARCHITECTURE.md §8 준수)

```
backend/
├── Dockerfile · docker-compose.yml · requirements.txt · .env.example
└── app/
    ├── main.py        FastAPI 진입점(라우터 마운트 + /health)
    ├── config.py      env 설정(pydantic-settings)
    ├── db.py          SQLAlchemy 세션 + Base
    ├── models.py      ORM (users·target_projects·scans·objectives·attempts·findings·attack_cases·atlas_techniques)
    ├── deps.py        get_current_user(JWT)
    ├── api/           라우트 (API-명세.md 섹션과 1:1)
    │   ├── auth.py        §1  로그인/OAuth/logout
    │   ├── projects.py    §2·3 레포목록·프로젝트 CRUD·정찰
    │   ├── scans.py       §4  스캔 시작/조회 + SSE
    │   └── results.py     §5  리포트·히트맵·findings·요약
    ├── engine/        진화 엔진(차별점) — ARCHITECTURE §4
    │   ├── orchestrator.py  루프(retrieve→select→mutate→fire→judge→update)
    │   ├── retrieve.py      벡터 코퍼스 씨앗 검색
    │   ├── select.py        UCB/MCTS
    │   ├── mutators.py      5연산자
    │   ├── actor.py         HttpActor(429 백오프)
    │   └── judge.py         3계층 판정(룰·라이브러리·Haiku)
    ├── tasks.py       비동기 스캔(PoC=BackgroundTasks / 운영=Celery)
    └── recon.py       정찰(repo grep+AST·프로빙)
```

## 담당 분배 (팀)

| 폴더/파일 | 담당 | 아키텍처 |
|---|---|---|
| `api/auth.py`, `deps.py` | auth | §2, §11.1 |
| `api/projects.py` (+ `recon.py`) | BE-API | §2 |
| `api/results.py` | 대시보드 | §5, §10 |
| `engine/*`, `tasks.py`, `api/scans.py` | **나(엔진)** | §4, §6, §7 |
| `models.py`, `db.py`, 인프라 | 공통(초기 세팅) | §8 |

## 데이터(코퍼스)
공격 씨앗 `attack_cases`(21k+임베딩)·`atlas_techniques`는 **별도 파이프라인**(`corpus_ingest.py`·`atlas_ingest.py`·`embed.py`) 산출물. 엔진만 읽음. 팀 공유 X, 배포 시 RDS로. `corpus.db`는 gitignore.

## PoC vs 운영 (ARCHITECTURE §5)
SQLite→Postgres, BackgroundTasks→Celery, 메타필터→pgvector HNSW 로 승격. 인터페이스 동일 → "바꾸면 돈다".
