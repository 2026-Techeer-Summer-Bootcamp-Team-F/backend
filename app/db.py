# -*- coding: utf-8 -*-
"""DB 세션 + Base. SQLAlchemy 2.0.

- 로컬 단독: sqlite (기본)  /  docker compose: postgres+pgvector (DATABASE_URL 주입)
- pgvector 벡터검색은 engine/retrieve.py 에서 사용(운영). PoC는 메타필터로도 가능.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """모든 ORM 모델의 부모. models.py 참조."""
    pass


def get_db():
    """FastAPI 의존성: 요청당 세션 하나."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
