# -*- coding: utf-8 -*-
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_db, Base
from app.models import User, TargetProject, Scan, Objective, Attempt, AtlasTechnique
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

SQLALCHEMY_TEST_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_TEST_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()

@pytest.fixture
def db():
    return TestingSessionLocal()

@pytest.fixture
def client():
    return TestClient(app)

def _seed(db):
    """테스트용 최소 데이터 세트 생성."""
    tech = AtlasTechnique(id="AML.T0054", name="LLM Jailbreak", tactic="", category="")
    db.add(tech)
    user = User(github_id="u1", github_name="u1", name="u1")
    db.add(user)
    db.flush()
    target = TargetProject(user_id=user.user_id, project_name="test")
    db.add(target)
    db.flush()
    scan = Scan(target_id=target.target_id, status="done")
    db.add(scan)
    db.flush()
    obj = Objective(scan_id=scan.scan_id, atlas_technique_id="AML.T0054", status="safe")
    db.add(obj)
    db.flush()
    a0 = Attempt(objective_id=obj.objective_id, parent_id=None,
                 prompt_text="seed prompt", generation=0,
                 mutation_op="", breached=False, fitness=0.3)
    db.add(a0)
    db.flush()
    a1 = Attempt(objective_id=obj.objective_id, parent_id=a0.attempt_id,
                 prompt_text="mutated prompt", generation=1,
                 mutation_op="roleplay",
                 breached=False, fitness=0.6)
    db.add(a1)
    db.commit()
    return scan.scan_id, obj.objective_id, user

def test_evolution_returns_nodes(client, db):
    scan_id, _, user = _seed(db)
    from app.deps import get_current_user
    app.dependency_overrides[get_current_user] = lambda: user
    resp = client.get(f"/scans/{scan_id}/evolution?atlas_id=AML.T0054")
    assert resp.status_code == 200
    data = resp.json()
    assert data["atlas_id"] == "AML.T0054"
    assert len(data["nodes"]) == 2

def test_evolution_node_fields(client, db):
    scan_id, _, user = _seed(db)
    from app.deps import get_current_user
    app.dependency_overrides[get_current_user] = lambda: user
    resp = client.get(f"/scans/{scan_id}/evolution?atlas_id=AML.T0054")
    nodes = resp.json()["nodes"]
    seed = next(n for n in nodes if n["generation"] == 0)
    assert seed["parent_id"] is None
    assert seed["verdict"] == "safe"
    assert seed["mutation_op"] == "seed"
    child = next(n for n in nodes if n["generation"] == 1)
    assert child["parent_id"] == seed["attempt_id"]
    assert child["mutation_op"] == "roleplay"

def test_evolution_unknown_atlas(client, db):
    scan_id, _, user = _seed(db)
    from app.deps import get_current_user
    app.dependency_overrides[get_current_user] = lambda: user
    resp = client.get(f"/scans/{scan_id}/evolution?atlas_id=AML.T9999")
    assert resp.status_code == 200
    assert resp.json()["nodes"] == []
