# -*- coding: utf-8 -*-
"""dev DB 재생성 — 모델(스키마) 변경 후 "코드 스키마 ≠ DB 스키마" 불일치 고치기.

배경: 앱은 부팅 시 `create_all()`로 테이블을 만드는데 이건 **없는 테이블만 생성**한다.
이미 있는 테이블에 컬럼을 추가(ALTER)하지 않으므로, 모델에 컬럼을 더해도 기존 테이블은
옛 스키마 그대로다 → `column users.github_name does not exist` 같은 500 발생.

이 스크립트: 사용자/스캔 계열 테이블을 drop 후 create_all로 **현재 모델대로 재생성**한다.
공격 코퍼스(attack_cases 21만)·ATLAS 마스터(atlas_techniques)는 **보존**(안 지움).

⚠️ dev 전용 — 스캔/사용자 테스트 데이터는 날아간다. 운영은 Alembic 마이그레이션을 쓸 것.
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/recreate_db.py
"""
import sys

from sqlalchemy import text

sys.path.insert(0, "/app")
from app.db import Base, SessionLocal, engine  # noqa: E402
from app import models  # noqa: E402,F401 — 모델을 Base.metadata에 등록
from app.models import AttackCase, AtlasTechnique, User  # noqa: E402

# 코퍼스(attack_cases)·atlas_techniques 빼고 = 사용자/스캔 계열만 drop(CASCADE로 FK 정리)
_DROP = ["scan_reports", "scan_events", "findings", "attempts",
         "objectives", "scans", "target_projects", "users"]


def main():
    with engine.begin() as c:
        for t in _DROP:
            c.execute(text(f'DROP TABLE IF EXISTS "{t}" CASCADE'))
    Base.metadata.create_all(bind=engine)   # drop된 것 + 없는 것 = 현재 모델대로 생성

    db = SessionLocal()
    print("✅ DB 재생성 완료 (현재 모델 스키마로)")
    print("   보존 attack_cases :", db.query(AttackCase).count())
    print("   보존 atlas        :", db.query(AtlasTechnique).count())
    print("   users(새 스키마)  :", db.query(User).count(), "명 (초기화됨)")


if __name__ == "__main__":
    main()
