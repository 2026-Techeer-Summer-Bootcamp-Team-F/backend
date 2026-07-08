# -*- coding: utf-8 -*-
"""§5 Results — 리포트·히트맵·Findings·AI요약. (담당: 대시보드)

전부 읽기 전용 집계 쿼리(scans/attempts/findings 조인). — API-명세.md §5
"""
from fastapi import APIRouter

router = APIRouter(prefix="/scans", tags=["results"])


@router.get("/{scan_id}/report")
def report(scan_id: int):
    """대시보드 통계 4개(risk_score·total_attempts·breached_attempts·findings). TODO"""
    return {"scan_id": scan_id, "stats": {}}


@router.get("/{scan_id}/heatmap")
def heatmap(scan_id: int):
    """ATLAS 기법별 침투율 히트맵(objectives↔atlas 집계). TODO"""
    return {"scan_id": scan_id, "cells": []}


@router.get("/{scan_id}/findings")
def findings(scan_id: int):
    """취약점 목록 + 완화책(findings→attempt→objective 조인). TODO"""
    return []


@router.get("/{scan_id}/summary")
def ai_summary(scan_id: int):
    """리포트 AI 요약(LLM). TODO"""
    return {"ai_summary": "TODO"}
