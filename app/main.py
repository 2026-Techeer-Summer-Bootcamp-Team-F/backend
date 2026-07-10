# -*- coding: utf-8 -*-
"""FastAPI 앱 진입점. — ARCHITECTURE.md §2 (플로우), API-명세.md (엔드포인트)

라우터 계층(api/)만 여기 마운트. 진화엔진(engine/)은 tasks 를 통해 비동기 실행.
실행:  uvicorn app.main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models  # noqa: F401 — ORM 모델을 Base.metadata 에 등록(create_all 전 필수)
from .api import auth, dummy, projects, results, scans
from .config import settings
from .db import Base, engine

# PoC: 부팅 시 테이블 자동 생성(운영은 Alembic 마이그레이션으로 교체)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Red-Team API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 관측성: Prometheus가 스크레이프할 /metrics 노출(설치돼 있을 때만). — ARCHITECTURE.md §3.11
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app)
except ImportError:  # 로컬 최소구성(미설치)에서도 앱은 정상 부팅
    pass

# ── 라우터 마운트 (API-명세.md 섹션과 1:1) ──
app.include_router(auth.router)        # §1 Auth
app.include_router(projects.router)    # §2·§3 GitHub Repos + Projects
app.include_router(scans.router)       # §4 Scans (+ SSE)
app.include_router(results.router)     # §5 Report/Heatmap/Findings
app.include_router(dummy.router)        # (PoC) 취약 더미앱 = self-testing 표적. 운영 배포 시 제외


@app.get("/health")
def health():
    return {"status": "ok", "auth_mode": settings.auth_mode,
            "db": settings.database_url.split(":", 1)[0]}
