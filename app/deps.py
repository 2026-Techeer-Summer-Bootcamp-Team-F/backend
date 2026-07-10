# -*- coding: utf-8 -*-
"""공통 의존성: 현재 사용자(JWT). — API-명세.md 인증 규칙(🔒)

HTTPBearer 스킴 사용 → Swagger UI 상단 'Authorize' 버튼으로 토큰을 한 번만 넣으면
보호 엔드포인트(🔒) 전체에 자동 적용된다(테스트 편의).
"""
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .db import get_db
from .models import User
from .security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(cred: HTTPAuthorizationCredentials = Depends(bearer_scheme),
                     db: Session = Depends(get_db)) -> User:
    """`Authorization: Bearer <jwt>` 검증 → User. 실패 시 401."""
    if cred is None or not cred.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "토큰 없음")
    try:
        payload = decode_access_token(cred.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "토큰 무효 또는 만료") from None
    sub = payload.get("sub")
    user = db.get(User, int(sub)) if sub else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "사용자 없음")
    return user
