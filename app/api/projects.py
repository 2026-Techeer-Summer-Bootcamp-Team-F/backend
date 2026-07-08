# -*- coding: utf-8 -*-
"""§2 GitHub Repos + §3 Projects — 레포목록·등록·수정·삭제·정찰. (담당: BE-API)"""
from fastapi import APIRouter

router = APIRouter(tags=["projects"])


@router.get("/github/repos")
def github_repos():
    """로그인 사용자 GitHub 레포 목록(Import 화면용). TODO: GitHub API 호출"""
    return []


@router.post("/projects", status_code=201)
def create_project():
    """레포 선택 → 동의+액터설정 등록. TODO"""
    return {"target_id": 0}


@router.get("/projects")
def list_projects():
    """등록된 내 프로젝트(대시보드 좌측). TODO"""
    return []


@router.get("/projects/{target_id}")
def get_project(target_id: int):
    return {"target_id": target_id}


@router.patch("/projects/{target_id}")
def update_project(target_id: int):
    """config·purpose·system_prompt 등 수정. TODO"""
    return {"target_id": target_id}


@router.delete("/projects/{target_id}", status_code=204)
def delete_project(target_id: int):
    """등록 해제(soft-delete). TODO"""
    return None


@router.post("/projects/{target_id}/recon")
def recon(target_id: int):
    """정찰 → model/defences/tools/rag_sources 갱신. engine/recon.py 호출. TODO"""
    return {"target_id": target_id, "status": "TODO"}
