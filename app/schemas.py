# -*- coding: utf-8 -*-
"""요청/응답 Pydantic 스키마. — API-명세.md 계약. 3.9 호환(Optional)."""
from typing import Optional

from pydantic import BaseModel


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
    target_id: int
    project_name: str
    actor_type: str        # config.actor_type 를 꺼내 노출(편의)
    config: dict
    system_prompt: str
    model: str
