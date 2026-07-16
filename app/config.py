# -*- coding: utf-8 -*-
"""환경설정 (pydantic-settings). .env 에서 로드. — ARCHITECTURE.md §11.3"""
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """앱 환경설정 값(.env·환경변수에서 로드). 비밀은 .env에만 두고 커밋 금지."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── 인증 ──
    auth_mode: str = "mock"                 # mock(dev-login) | github(OAuth)
    jwt_secret: str = "dev-secret-change-in-prod-0123456789abcdef"  # ≥32B, Prod 교체
    jwt_alg: str = "HS256"
    jwt_expire_min: int = 60 * 24

    # ── 배포 형태 ── 클라우드(EC2 등)에 배포돼 스캐너와 표적이 다른 머신인지.
    # True면 표적의 localhost/host.docker.internal은 스캐너에서 안 닿으므로 자동감지가
    # 로컬 주소를 강요하지 않고 공개 URL(터널)을 안내한다. (prod compose에서 "1")
    public_deployment: bool = False

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

    # ── 관측성: Langfuse (LLM 호출 트레이싱; 키 없으면 자동 비활성=no-op) ──
    # judge Tier3·코드스캐너·리포트요약의 Haiku 호출을 트레이싱(지연·토큰·비용·플로우).
    # ⚠️ 마스킹 ON이 기본 — 프롬프트/표적응답 '원문'은 Langfuse로 안 보내고 길이·메타만 전송
    #    (보안도구가 캐낸 유출데이터를 제3자 SaaS에 흘리지 않도록). host는 리전별 주소.
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    # env: LANGFUSE_HOST (구 LANGFUSE_BASE_URL 도 허용). JP 리전 예: https://jp.cloud.langfuse.com
    langfuse_host: str = Field(
        default="", validation_alias=AliasChoices("LANGFUSE_HOST", "LANGFUSE_BASE_URL"))
    langfuse_mask: bool = True   # False로 두면 원문까지 전송(권장 X)

    # ── RabbitMQ (Celery 메시지 브로커 — 태스크 배달) — 2026-07-10 브로커 분리 ──
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672//"

    # ── Redis (3역할: 캐시(벡터검색 결과)·rate-limit·Celery result backend) ──
    redis_url: str = "redis://localhost:6379/0"


settings = Settings()
