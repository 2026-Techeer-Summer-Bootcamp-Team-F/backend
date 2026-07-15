# -*- coding: utf-8 -*-
"""소유권(객체수준 인가) 헬퍼 — 스캔/목표/시도가 '이 사용자 것'인지 검증. (#91)

문제: 조회·취소·생성·스트림 엔드포인트가 로그인만 요구하고 소유권을 안 봐서, ID만 알면
남의 스캔·리포트·증거를 볼 수 있었다(IDOR / OWASP API1).

Scan엔 user_id가 없다 → 소유권은 `Scan.target_id → TargetProject.user_id`로 거슬러 확인.
Objective/Attempt는 scan을 거쳐 같은 방식. 서비스 로직은 안 바꾸고 접근 통제만 추가한다.

보안: 남의 리소스이거나 없으면 **404**(존재 자체를 숨겨 ID 열거를 막음). 삭제(DELETE)만은
기존 계약대로 403을 유지(그쪽은 이미 소유권 검증됨).
"""
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .models import Attempt, Objective, Scan, TargetProject


def _not_found(msg: str = "스캔 없음"):
    raise HTTPException(status.HTTP_404_NOT_FOUND, msg)


def scan_owned_or_404(db: Session, scan_id: int, user) -> Scan:
    """scan이 user 소유면 반환, 아니면 404. (Scan → target_projects.user_id)"""
    scan = db.get(Scan, scan_id)
    if scan is None:
        _not_found()
    target = db.get(TargetProject, scan.target_id)
    if target is None or target.user_id != user.user_id:
        _not_found()
    return scan


def scan_owned_by_uid(db: Session, scan_id: int, user_id: int) -> bool:
    """user_id(정수)로 소유 여부만 bool 반환 — SSE 등 User 객체가 없는 경로용."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        return False
    target = db.get(TargetProject, scan.target_id)
    return target is not None and target.user_id == user_id


def objective_owned_or_404(db: Session, objective_id: int, user) -> Objective:
    """objective가 user 소유의 스캔에 속하면 반환, 아니면 404."""
    obj = db.get(Objective, objective_id)
    if obj is None:
        _not_found("목표 없음")
    scan_owned_or_404(db, obj.scan_id, user)  # 소속 스캔 소유권 확인(아니면 404)
    return obj


def attempt_owned_or_404(db: Session, attempt_id: int, user) -> Attempt:
    """attempt가 user 소유의 스캔에 속하면 반환, 아니면 404."""
    at = db.get(Attempt, attempt_id)
    if at is None:
        _not_found("시도 없음")
    obj = db.get(Objective, at.objective_id)
    if obj is None:
        _not_found("시도 없음")
    scan_owned_or_404(db, obj.scan_id, user)
    return at
