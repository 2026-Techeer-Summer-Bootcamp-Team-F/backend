# -*- coding: utf-8 -*-
"""공통 의존성: 현재 사용자(JWT). — API-명세.md 인증 규칙(🔒)"""
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .db import get_db
from .models import User


def get_current_user(authorization: str = Header(default=""),
                     db: Session = Depends(get_db)) -> User:
    """`Authorization: Bearer <jwt>` 검증 → User. TODO: JWT 디코드(auth 담당)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "토큰 없음")
    # TODO: jwt.decode(token, settings.jwt_secret) → user_id → User 조회
    raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "JWT 검증 미구현(auth 담당)")
