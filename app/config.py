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

    # ── 정찰: LLM 통합 판단 (ast/grep 좁힌 코드를 Haiku가 종합·앱파악) — #130 ──
    # 기본 OFF = 기존 ast+grep만. ON 하면 Haiku가 도메인·위험 판단 추가.
    # 키없음/실패 시 결정론(ast+grep) 결과만으로 폴백.
    recon_llm_enabled: bool = True

    # ── 자기강화: 뚫은 공격을 attack_cases에 되먹임(자가진화 DB) — 로드맵 "데이터베이스 강화" ──
    # ON = 스캔 done 시 breach된 시도를 필터·dedup해 source="self_learned"로 되먹임.
    # 뚫린 성공 프롬프트는 그 즉시 384d 벡터변환 + verified=True 적재 → 다음 스캔 retrieve 편입.
    # 오탐/편중은 표적특정 필터(카나리·URL·앱이름) + 기법당 fitness top_k로 걸러진다.
    # (promote_hits≥2로 올리면 "재현돼야 편입"하는 묵혀두기 모드 — 진화가 같은 프롬프트를 잘
    #  재발사 안 해 실제론 거의 안 쌓임 → 기본은 즉시편입=1.)
    # 실패해도 스캔은 정상 종료(try/except). 롤백: DELETE FROM attack_cases WHERE source='self_learned'.
    corpus_feedback_enabled: bool = True
    corpus_feedback_top_k: int = 3        # 기법(atlas)당 fitness 상위 K개만 적재(폭증 차단)
    corpus_feedback_min_len: int = 15     # 프롬프트 최소 길이(공백 제외; 너무 짧은 잡음 컷)
    corpus_feedback_promote_hits: int = 1  # 편입 임계. 1=뚫리면 즉시(기본) / ≥2=재현돼야(묵혀두기)

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
