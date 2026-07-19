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
    # repos(비공개 포함) 조회 위해 repo, 스캔완료 리포트 메일 발송 위해 user:email 스코프.
    github_scope: str = "read:user repo user:email"
    frontend_url: str = "http://localhost:5173"

    # ── 이메일 리포트 발송 (스캔완료 시 AI요약+링크) ──
    # provider: ses(AWS SES, boto3) | resend | console(로컬: 실제발송 X, 내용만 로그).
    # 수신자=표적 소유자 user.email(GitHub user:email) → 없으면 dev_test_email(로컬 mock).
    email_provider: str = "console"         # ses | resend | console
    email_from: str = "AI RedTeam 리포트 <onboarding@resend.dev>"  # SES 샌드박스면 verified 주소여야
    email_reply_to: str = ""                # 답장 받을 주소(옵션)
    dev_test_email: str = ""                # mock/dev-login 유저에 채울 테스트 수신주소
    ses_region: str = "ap-northeast-2"      # SES 리전(서울)
    resend_api_key: str = ""                # EMAIL_PROVIDER=resend 일 때

    # ── GitHub 토큰 저장 암호화(옵션) ──
    token_enc_key: str = ""                 # 있으면 Fernet 암호화, 없으면 평문(PoC)

    # ── 공격자 LLM (변이/판정 폴백; 비우면 결정론적 변이만) ──
    anthropic_api_key: str = ""
    attacker_model: str = "claude-haiku-4-5-20251001"

    # ── 씨앗 검색: 벡터 의미검색 (정찰정보 질의 임베딩) — #130 ──
    # 기본 OFF = 기존 메타필터(하위호환). ON 하려면 fastembed 필요(RAM~90MB 로드).
    # 로드 실패/임베딩 없음 → retrieve가 메타필터로 자동 폴백(안 죽음).
    retrieve_vector_enabled: bool = True
    # 코퍼스 임베딩과 '같은 모델'이라야 코사인이 의미 있음(load_corpus embedding = 384d all-MiniLM).
    embed_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    retrieve_candidate_cap: int = 2000   # 벡터랭킹 후보 상한(메모리·시간)

    # ── 판정: AI 우선 (카나리·거절만 룰 확정 → 나머지 Haiku 최종판정) — #130 ──
    # 기본 OFF = 기존(0.45~0.8 애매구간만 Haiku). ON 하면 룰로 못 가른 것 전부 AI.
    # 키 없거나 실패 시 휴리스틱 폴백(안 끊김).
    judge_ai_primary: bool = True

    # ── 공격자: AI 공격 생성 (교본 사다리 타며 응답 보고 다음 공격) — #130 ──
    # 기본 OFF = 기존 결정론 변이(랜덤 6연산자). ON 하면 Haiku가 다음 공격 설계.
    # 거부/키없음/실패 시 결정론 변이로 폴백(안 끊김).
    attacker_ai_enabled: bool = True

    # ── 멀티턴(Crescendo): 한 에피소드=여러 턴 대화로 점진 유도 — #138 ──
    # 기본 OFF = 기존 단발 진화만(오늘과 100% 동일). ON 하면 0세대 씨앗이 안 뚫었을 때
    # actor 세션을 유지한 채 Haiku가 턴마다 '직전 응답 인용→한 단계 escalate'로 대화를 끈다.
    # 정렬모델(Claude 등) 대상 지렛대. 각 턴=Attempt(parent=직전 턴)라 트리/대화 UI 그대로.
    multiturn_enabled: bool = False
    multiturn_max_turns: int = 3   # 한 에피소드 최대 턴(토큰·밴 방어 상한; 정체/에러 시 더 일찍 끊김)

    # ── 정찰: LLM 통합 판단 (ast/grep 좁힌 코드를 Haiku가 종합·앱파악) — #130 ──
    # 기본 OFF = 기존 ast+grep만. ON 하면 Haiku가 도메인·위험 판단 추가.
    # 키없음/실패 시 결정론(ast+grep) 결과만으로 폴백.
    recon_llm_enabled: bool = True

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
