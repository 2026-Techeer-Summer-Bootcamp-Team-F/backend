# -*- coding: utf-8 -*-
"""SQLAlchemy ORM 모델 (정규화 ERD 기준). — 정본: docs/ERD-완전정리.md

⚠️ 컬럼 세부는 ERD-완전정리.md 최종본과 대조해 확정할 것(여긴 뼈대).
표적=projects(target_projects), 스캔결과 체인: scan → objective → attempt → finding.
공격 코퍼스(attack_cases)·ATLAS 마스터(atlas_techniques)는 corpus_ingest/atlas_ingest 산출물.
"""
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String,
                        Text)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    github_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    github_login: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class TargetProject(Base):
    """등록된 표적 앱(= import 한 GitHub 레포 1개). API: /projects"""
    __tablename__ = "target_projects"
    target_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"), index=True)
    project_name: Mapped[str] = mapped_column(String)
    repo_url: Mapped[str] = mapped_column(String, default="")
    purpose: Mapped[str] = mapped_column(Text, default="")
    system_prompt: Mapped[str] = mapped_column(Text, default="")
    config: Mapped[dict] = mapped_column(JSON, default=dict)     # 액터 config(url·model 등)
    # 정찰 결과 필드
    model: Mapped[str] = mapped_column(String, default="")
    defences: Mapped[dict] = mapped_column(JSON, default=dict)
    tools: Mapped[dict] = mapped_column(JSON, default=dict)
    rag_sources: Mapped[dict] = mapped_column(JSON, default=dict)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # soft-delete
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Scan(Base):
    __tablename__ = "scans"
    scan_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("target_projects.target_id"), index=True)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending/running/done/failed
    config: Mapped[dict] = mapped_column(JSON, default=dict)        # attack_types 등 요청 원본
    progress: Mapped[dict] = mapped_column(JSON, default=dict)      # generation/best_score/phase
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Objective(Base):
    """스캔 목표(attack_type → atlas 기법으로 변환된 레코드)."""
    __tablename__ = "objectives"
    objective_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    atlas_technique_id: Mapped[str] = mapped_column(ForeignKey("atlas_techniques.id"))
    status: Mapped[str] = mapped_column(String, default="pending")


class Attempt(Base):
    """개별 공격 시도(진화 계보 = parent_id). fire→judge 1회."""
    __tablename__ = "attempts"
    attempt_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    objective_id: Mapped[int] = mapped_column(ForeignKey("objectives.objective_id"), index=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("attempts.attempt_id"), nullable=True)
    prompt_text: Mapped[str] = mapped_column(Text)
    response_text: Mapped[str] = mapped_column(Text, default="")
    fitness: Mapped[float] = mapped_column(default=0.0)
    generation: Mapped[int] = mapped_column(Integer, default=0)
    mutation_op: Mapped[str] = mapped_column(String, default="")
    breached: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Finding(Base):
    """확정된 취약점(뚫린 attempt). 정규화: attempt_id 하나로 계보 도달."""
    __tablename__ = "findings"
    findings_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attempt_id: Mapped[int] = mapped_column(ForeignKey("attempts.attempt_id"), index=True)
    severity: Mapped[str] = mapped_column(String, default="")       # low/medium/high/critical
    evidence: Mapped[str] = mapped_column(Text, default="")         # 카나리 매치·응답 스니펫
    mitigation: Mapped[str] = mapped_column(Text, default="")       # 시점 스냅샷
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ScanEvent(Base):
    """SSE 재생/유실복구용 이벤트 로그(순번 = id)."""
    __tablename__ = "scan_events"
    scan_events_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ScanReport(Base):
    """스캔 리포트 = 대시보드 통계 원본. API §5 /scans/{id}/report."""
    __tablename__ = "scan_reports"
    report_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), index=True, unique=True)
    risk_score: Mapped[float] = mapped_column(default=0.0)          # 위험도
    total_attempts: Mapped[int] = mapped_column(Integer, default=0)  # 총 시도
    breached_attempts: Mapped[int] = mapped_column(Integer, default=0)  # 뚫린 시도
    findings_count: Mapped[int] = mapped_column(Integer, default=0)  # 취약점 수
    ai_summary: Mapped[str] = mapped_column(Text, default="")        # LLM 요약(§5)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


# ── 공격 코퍼스 (corpus_ingest.py 산출물 = 씨앗 검색 대상) ──
class AttackCase(Base):
    __tablename__ = "attack_cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prompt_text: Mapped[str] = mapped_column(Text)
    attack_type: Mapped[str] = mapped_column(String, index=True)
    atlas_technique_id: Mapped[str] = mapped_column(ForeignKey("atlas_techniques.id"))
    source: Mapped[str] = mapped_column(String, index=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    embedding: Mapped[list | None] = mapped_column(JSON, nullable=True)  # 운영: Vector(384)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class AtlasTechnique(Base):
    """ATLAS 기법 마스터 (atlas_ingest.py). 공식 mitre-atlas 기준."""
    __tablename__ = "atlas_techniques"
    id: Mapped[str] = mapped_column(String, primary_key=True)   # 예: AML.T0054
    name: Mapped[str] = mapped_column(String)
    tactic: Mapped[str] = mapped_column(String, default="")
    category: Mapped[str] = mapped_column(String, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    mitigation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
