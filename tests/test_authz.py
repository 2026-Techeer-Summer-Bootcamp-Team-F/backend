# -*- coding: utf-8 -*-
"""소유권(인가) 헬퍼 단위테스트 — 남의 스캔/목표/시도 접근이 404로 막히는지. (#91)

DB 없이 FakeDB(모델별 id→객체 매핑)로 순수 로직만 검증.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import authz
from app.models import Attempt, Objective, Scan, TargetProject


class FakeDB:
    """db.get(Model, id) → 미리 심어둔 객체 반환(모델명 기준)."""

    def __init__(self, **tables):
        self._t = tables  # {"Scan": {id: obj}, ...}

    def get(self, model, key):
        return self._t.get(model.__name__, {}).get(key)


def _user(uid):
    return SimpleNamespace(user_id=uid)


def _owned_db():
    return FakeDB(
        Scan={1: SimpleNamespace(scan_id=1, target_id=10)},
        TargetProject={10: SimpleNamespace(target_id=10, user_id=7)},
        Objective={3: SimpleNamespace(objective_id=3, scan_id=1)},
        Attempt={5: SimpleNamespace(attempt_id=5, objective_id=3)},
    )


def test_scan_owned_ok():
    scan = authz.scan_owned_or_404(_owned_db(), 1, _user(7))
    assert scan.scan_id == 1


def test_scan_not_owned_is_404():
    with pytest.raises(HTTPException) as e:
        authz.scan_owned_or_404(_owned_db(), 1, _user(999))
    assert e.value.status_code == 404


def test_scan_missing_is_404():
    db = FakeDB(Scan={}, TargetProject={})
    with pytest.raises(HTTPException) as e:
        authz.scan_owned_or_404(db, 42, _user(7))
    assert e.value.status_code == 404


def test_scan_owned_by_uid_bool():
    db = _owned_db()
    assert authz.scan_owned_by_uid(db, 1, 7) is True       # 본인
    assert authz.scan_owned_by_uid(db, 1, 8) is False      # 남
    assert authz.scan_owned_by_uid(db, 999, 7) is False    # 없음


def test_attempt_owned_chain():
    at = authz.attempt_owned_or_404(_owned_db(), 5, _user(7))
    assert at.attempt_id == 5


def test_attempt_not_owned_is_404():
    with pytest.raises(HTTPException) as e:
        authz.attempt_owned_or_404(_owned_db(), 5, _user(1))
    assert e.value.status_code == 404


def test_objective_owned_chain():
    obj = authz.objective_owned_or_404(_owned_db(), 3, _user(7))
    assert obj.objective_id == 3


def test_objective_not_owned_is_404():
    with pytest.raises(HTTPException) as e:
        authz.objective_owned_or_404(_owned_db(), 3, _user(1))
    assert e.value.status_code == 404
