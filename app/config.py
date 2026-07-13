# -*- coding: utf-8 -*-
"""환경설정 (pydantic-settings). .env 에서 로드. — ARCHITECTURE.md §11.3"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """앱 환경설정 값(.env·환경변수에서 로드). 비밀은 .env에만 두고 커밋 금지."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── 인증 ──
    auth_mode: str = "mock"                 # mock(dev-login) | github(OAuth)
    jwt_secret: str = "dev-secret-change-in-prod-0123456789abcdef"  # ≥32B, Prod 교체
    jwt_alg: str = "HS256"
    jwt_expire_min: int = 60 * 24

    # ── DB (compose가 postgres 주입; 로컬 단독 실행 기본은 sqlite) ──
    database_url: str = "sqlite:///./redteam.db"

    # ── GitHub OAuth (auth_mode=github 일 때) ──
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = "http://localhost:5173/auth/callback"
    github_scope: str = "read:user repo"    # repos(비공개 포함) 조회 위해 repo 스코프
    frontend_url: str = "http://localhost:5173"

    # ── GitHub 토큰 저장 암호화(옵션) ──
    token_enc_key: str = ""                 # 있으면 Fernet 암호화, 없으면 평문(PoC)

    # ── 공격자 LLM (변이/판정 폴백; 비우면 결정론적 변이만) ──
    anthropic_api_key: str = ""
    attacker_model: str = "claude-haiku-4-5-20251001"

    # ── RabbitMQ (Celery 메시지 브로커 — 태스크 배달) — 2026-07-10 브로커 분리 ──
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672//"

    # ── Redis (3역할: 캐시(벡터검색 결과)·rate-limit·Celery result backend) ──
    redis_url: str = "redis://localhost:6379/0"


settings = Settings()
