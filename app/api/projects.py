# -*- coding: utf-8 -*-
"""§2 GitHub Repos + §3 Projects — 레포목록·등록·수정·삭제·정찰. (담당: BE-API)

`POST /projects/{id}/actor`(액터 구성 저장)는 엔진(사용자) 스코프 — 스캔이 읽을
config 스키마를 정의하는 쪽이라 여기서 구현. 소유권 검증은 get_current_user(팀원 auth) 의존.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user
from ..models import TargetProject, User
from ..recon import profile_target
from ..schemas import ActorSaveIn

router = APIRouter(tags=["projects"])

_VALID_ACTOR_TYPES = {"http", "browser"}


def _project_out(t: TargetProject) -> dict:
    return {"target_id": t.target_id, "project_name": t.project_name,
            "actor_type": (t.config or {}).get("actor_type", ""),
            "config": t.config or {}, "system_prompt": t.system_prompt, "model": t.model}


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


@router.post("/projects/{target_id}/actor")
def save_actor(target_id: int, body: ActorSaveIn,
               db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    """액터 구성 저장 — 동의 후 '액터 정보 입력' 화면에서 제출.

    config(JSON)에 액터 설정 저장. actor_type은 config 안(DB 컬럼 아님).
    system_prompt·model은 전용 컬럼. 스캔 엔진이 이 config를 읽어 액터 생성→발사.
    """
    target = db.get(TargetProject, target_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "프로젝트 없음")
    if target.user_id != user.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "본인 프로젝트만 수정 가능")

    cfg = body.config or {}
    actor_type = cfg.get("actor_type")
    if actor_type not in _VALID_ACTOR_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"config.actor_type 필수 (http|browser), 받음={actor_type!r}")
    if not cfg.get("url"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "config.url 필수")
    if actor_type == "browser":
        for req in ("input_selector", "output_selector"):
            if not cfg.get(req):
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"browser: config.{req} 필수")

    target.config = cfg                                   # 액터 설정 저장(JSON)
    if body.system_prompt is not None:                    # 전용 컬럼
        target.system_prompt = body.system_prompt
    if body.model is not None:
        target.model = body.model
    db.commit()
    db.refresh(target)
    return _project_out(target)


@router.post("/projects/{target_id}/recon")
def recon(target_id: int, db: Session = Depends(get_db),
          user: User = Depends(get_current_user)):
    """정찰 실행 → target_projects.model/defences/tools/rag_sources 갱신. recon.py 호출.

    코드 소스는 config.source_path(로컬) 우선, 없으면 등록입력만. repo fetch는 팀원 auth 대기.
    save_actor와 동일하게 인증+소유권 검증(본인 프로젝트만).
    """
    target = db.get(TargetProject, target_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "프로젝트 없음")
    if target.user_id != user.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "본인 프로젝트만 정찰 가능")
    profile = profile_target(target)
    target.model = profile["model"] or target.model
    if profile["system_prompt"]:
        target.system_prompt = profile["system_prompt"]
    target.defences = {"detected": profile["defenses"]}
    target.tools = {"detected": profile["tools"]}
    target.rag_sources = {"detected": profile["rag_sources"]}
    db.commit()
    db.refresh(target)
    return {"target_id": target_id, "profile": profile}
