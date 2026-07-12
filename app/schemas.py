# -*- coding: utf-8 -*-
"""요청/응답 Pydantic 스키마. — API-명세.md 계약. 3.9 호환(Optional)."""
from typing import Optional

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    """POST /scans — 스캔 트리거. (§4)

    target_id = 공격할 표적(등록된 프로젝트). config = 자유 JSON:
    attack_types[]·population_size·max_generations·auth_context·safe_mode 등
    (세부 검증·objectives 매핑은 후속 이슈. #36은 관통 뼈대).
    """
    target_id: int
    config: dict = Field(default_factory=dict)


class DevLoginIn(BaseModel):
    """POST /auth/dev-login — PoC 전용(AUTH_MODE=mock). GitHub 없이 토큰 발급."""
    github_name: str
    name: str = ""


class ActorSaveIn(BaseModel):
    """POST /projects/{id}/actor — 액터 구성 저장.

    `config`는 자유 JSON(액터별 필드)이라 dict로 받되, 엔드포인트에서
    actor_type·url 필수 검증. 비밀은 값이 아니라 env 변수명(*_env)만 담긴다.
    system_prompt·model은 config가 아닌 전용 컬럼(정찰 결과와 일관).
    """
    config: dict
    system_prompt: Optional[str] = None
    model: Optional[str] = None


class ProjectOut(BaseModel):
    """프로젝트 응답 스키마 — 액터 config와 전용 컬럼을 노출."""
    target_id: int
    project_name: str
    actor_type: str        # config.actor_type 를 꺼내 노출(편의)
    config: dict
    system_prompt: str
    model: str


class ProjectCreateIn(BaseModel):
    """POST /projects — 대상 앱 등록. (§3)

    `actor_type`은 요청 top-level로 받되 저장은 `config` 안에 병합(DB 별도 컬럼 없음,
    save_actor와 동일 규칙). 등록 시 config 상세검증은 느슨(url·셀렉터 등은 이후
    POST /projects/{id}/actor에서 검증). 비밀은 값이 아니라 env 변수명(*_env)만.
    """
    project_name: str
    actor_type: str
    config: dict = Field(default_factory=dict)
    purpose: Optional[str] = None
    system_prompt: Optional[str] = None
    repo_url: Optional[str] = None


class ProjectUpdateIn(BaseModel):
    """PATCH /projects/{id} — 부분 수정. 전달된 필드만 반영(§3)."""
    project_name: Optional[str] = None
    config: Optional[dict] = None
    purpose: Optional[str] = None
    system_prompt: Optional[str] = None
    repo_url: Optional[str] = None
