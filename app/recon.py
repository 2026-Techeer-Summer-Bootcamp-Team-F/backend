# -*- coding: utf-8 -*-
"""정찰(Recon) — 표적 AI앱 프로파일 추출(무료: ast+grep, AI 0원). — 계획 §2-A·§2-B-1

리포/소스 코드를 ast(구조) + 정규식(grep)으로 훑어 5가지 추출:
model·system_prompt·tools·defenses·rag_sources. 이 프로파일 → 공격유형(objectives) 규칙 매핑.

⚠️ 특정 앱에 하드코딩 아님 — 아무 챗봇 레포나 훑는 범용 엔진. 실제 표적은 팀원이
   레포로 만드는 공격용 챗봇(대상은 config.source_path/repo로 갈아끼움).
⚠️ 리포 코드 fetch는 OAuth `repo` 스코프(팀원 auth) 필요 = 크로스팀 의존.
   엔진(ast/grep)은 무료·완성이고 "코드를 어디서 가져오나"만 팀원 auth 대기.
"""
import ast
import logging
import re
from pathlib import Path

log = logging.getLogger("redteam.recon")

# ── 추출 규칙(정규식 grep) ──
_MODEL_PAT = re.compile(
    r"\b(gpt-4o|gpt-4[\w.-]*|gpt-3\.5[\w.-]*|o[13][\w-]*|claude-[\w.-]+|"
    r"gemini[\w.-]*|llama[\w.-]*|mistral[\w.-]*|mixtral[\w.-]*|qwen[\w.-]*)\b", re.I)
_TOOL_HINTS = ("transfer", "send_email", "sendmail", "send_mail", "payment",
               "refund", "wire", "delete_", "query_db", "execute_sql",
               "book_", "checkout", "invoice", "place_order")
_DEFENSE_HINTS = ("moderat", "guardrail", "refus", "sanitiz", "blocklist",
                  "blacklist", "allowlist", "content_filter", "safety",
                  "jailbreak", "injection", "policy")
_RAG_HINTS = ("retriev", "vectorstore", "vector_store", "embedding", "faiss",
              "pinecone", "chroma", "weaviate", "knowledge_base", "rag",
              ".pdf", ".txt", ".csv", "documentloader", "loader(")
# system_prompt 로 볼 변수명(소문자)
_SYS_NAMES = {"system", "system_prompt", "systemprompt", "sys_prompt",
              "prompt", "instructions", "persona", "_system"}
# system_prompt 텍스트에서 도구 신호로 볼 단어(은행앱 등 자연어 힌트)
_PROMPT_TOOL_HINTS = ("transfer", "card", "account", "refund", "payment", "wire")

# ── 공격유형 문자열 → ATLAS id (계획 §2-B-1) ──
_TYPE_TO_ATLAS = {
    "jailbreak": "AML.T0054",
    "prompt_injection": "AML.T0051.000",
    "direct_injection": "AML.T0051.000",
    "indirect_injection": "AML.T0051.001",
    "rag_injection": "AML.T0051.001",
    "data_leakage": "AML.T0056",
    "system_prompt_leak": "AML.T0056",
    "prompt_leak": "AML.T0056",
    "tool_misuse": "AML.T0053",
    "excessive_agency": "AML.T0053",
    "pii": "AML.T0057",
    "pii_leak": "AML.T0057",
}


class _ProfileVisitor(ast.NodeVisitor):
    """ast로 system_prompt 문자열 할당 + 함수 정의명 수집."""

    def __init__(self):
        self.system_prompts = []
        self.func_names = []

    def visit_FunctionDef(self, node):
        self.func_names.append(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.func_names.append(node.name)
        self.generic_visit(node)

    def visit_Assign(self, node):
        names = [t.id.lower() for t in node.targets if isinstance(t, ast.Name)]
        if any(n in _SYS_NAMES for n in names):
            txt = _const_str(node.value)
            if txt:
                self.system_prompts.append(txt)
        self.generic_visit(node)


def _const_str(node):
    """AST 노드에서 문자열 리터럴 뽑기(상수 + 괄호 연결 + f-string 정적부분)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (_const_str(node.left) or "") + (_const_str(node.right) or "")
    if isinstance(node, ast.JoinedStr):  # f"..." — 정적 텍스트만
        return "".join(v.value for v in node.values
                       if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _grep(hints, text_low) -> list:
    return sorted({h for h in hints if h in text_low})


def profile_target(target, source=None) -> dict:
    """표적 → 프로파일 dict.

    source(코드 문자열) 없으면 config.source_path(로컬 경로) 읽고, 그것도 없으면
    등록입력(model/system_prompt)만으로 최소 프로파일. — 계획 §2-A(3소스 정확도순).
    """
    src = source
    cfg = getattr(target, "config", None) or {}
    if src is None and cfg.get("source_path"):
        try:
            src = Path(cfg["source_path"]).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            log.warning("recon: source_path 못 읽음: %s", cfg.get("source_path"))

    if src is None:
        # 리포 코드 없음(repo 스코프 미보유 등) → 등록입력만(블랙박스는 후속)
        sp = getattr(target, "system_prompt", "") or ""
        return {"model": getattr(target, "model", "") or "", "system_prompt": sp,
                "has_system_prompt": bool(sp), "tools": [], "defenses": [],
                "rag_sources": [], "source": "registered"}

    low = src.lower()
    # ast(구조): system_prompt·함수명 (파이썬 아니면 grep만)
    prompts, func_names = [], []
    try:
        v = _ProfileVisitor()
        v.visit(ast.parse(src))
        prompts, func_names = v.system_prompts, v.func_names
    except (SyntaxError, ValueError, RecursionError):
        # SyntaxError=파이썬 아님/문법오류, ValueError=NUL바이트 소스, RecursionError=초깊은 AST
        pass

    system_prompt = max(prompts, key=len) if prompts else (getattr(target, "system_prompt", "") or "")
    m = _MODEL_PAT.search(src)
    model = m.group(0) if m else (getattr(target, "model", "") or "")

    func_low = " ".join(func_names).lower()
    tools = sorted(set(_grep(_TOOL_HINTS, low)
                       + _grep(_TOOL_HINTS, func_low)
                       + _grep(_PROMPT_TOOL_HINTS, system_prompt.lower())))
    return {"model": model, "system_prompt": system_prompt,
            "has_system_prompt": bool(system_prompt), "tools": tools,
            "defenses": _grep(_DEFENSE_HINTS, low),
            "rag_sources": _grep(_RAG_HINTS, low), "source": "repo"}


def attack_types_to_atlas(types) -> list:
    """사용자가 고른 attack_types(문자열) → ATLAS id 목록(중복 제거·순서 유지)."""
    out = []
    for t in types or []:
        a = _TYPE_TO_ATLAS.get(str(t).strip().lower())
        if a:
            out.append(a)
    return list(dict.fromkeys(out))


def profile_to_atlas(profile) -> list:
    """정찰 프로파일 → 넣을 공격(objectives) ATLAS id (계획 §2-B-1 규칙 lookup).

    defenses 유무는 여기서 objective를 가르지 않고(직접인젝션·탈옥은 항상 기본),
    '우회 씨앗 우선'은 retrieve(#38) 단계의 필터로 반영한다.
    """
    out = []
    if profile.get("tools"):
        out.append("AML.T0053")          # 도구 오용·과잉권한
    if profile.get("rag_sources"):
        out.append("AML.T0051.001")      # 간접 프롬프트 인젝션
    if profile.get("has_system_prompt"):
        out.append("AML.T0056")          # 프롬프트/데이터 유출
    out.append("AML.T0051.000")          # 직접 프롬프트 인젝션(기본)
    out.append("AML.T0054")              # 탈옥(우회, 기본)
    return list(dict.fromkeys(out))
