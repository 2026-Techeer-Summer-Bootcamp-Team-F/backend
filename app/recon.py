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
import time
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
    # 단어형 힌트(rag 등)는 '앞 경계'를 요구해 오탐 방지(rag ⊂ sto"rag"e). 앞 경계만 두므로
    # 스템 매칭은 유지 — retriev→retrieval, refus→refuses 같은 접두 일치는 그대로 잡힌다.
    # 특수문자 포함 힌트(.pdf·loader( 등)는 부분일치 유지.
    out = set()
    for h in hints:
        if h.replace("_", "").isalnum():
            if re.search(r"(?<![a-z0-9])" + re.escape(h), text_low):
                out.add(h)
        elif h in text_low:
            out.add(h)
    return sorted(out)


_ALLOWED_BASE = Path.cwd().resolve()   # 컨테이너 작업 디렉터리(=/app). 이 밖은 못 읽음.


def _read_source(source_path: str):
    """config.source_path를 승인된 작업 디렉터리 안으로 제한해 읽는다.

    경로 탈출(`../`)·절대경로로 `/etc/passwd` 같은 임의 파일을 읽는 것을 막는다(정찰은
    사용자 config를 그대로 받으므로). 밖이거나 못 읽으면 None → 등록입력만으로 폴백.
    """
    try:
        base = _ALLOWED_BASE
        p = Path(source_path)
        p = (p if p.is_absolute() else base / p).resolve()
        if base != p and base not in p.parents:
            log.warning("recon: source_path가 허용 디렉터리 밖 — 무시: %s", source_path)
            return None
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        log.warning("recon: source_path 못 읽음: %s", source_path)
        return None


def profile_target(target, source=None) -> dict:
    """표적 → 프로파일 dict.

    source(코드 문자열) 없으면 config.source_path(로컬 경로) 읽고, 그것도 없으면
    등록입력(model/system_prompt)만으로 최소 프로파일. — 계획 §2-A(3소스 정확도순).
    """
    src = source
    cfg = getattr(target, "config", None) or {}
    if src is None and cfg.get("source_path"):
        src = _read_source(cfg["source_path"])

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


# ─────────────────────────────────────────────────────────────────────────────
# HTTP 계약 자동 감지 (표적 등록 마찰 감소) — 레포 코드에서 요청필드·응답경로·라우트 추출.
# promptfoo/garak의 "HTTP 템플릿" 패턴을 자동으로 채워주는 휴리스틱. 못 찾으면 None → 폴백.
# ─────────────────────────────────────────────────────────────────────────────

# 요청 본문 필드 후보를 뽑는 정규식 (그룹1=필드명). FastAPI/Flask/Express/stdlib 공통.
_REQ_FIELD_PATS = [
    re.compile(r"""\.get\(\s*["'](\w+)["']"""),        # data.get("message")
    re.compile(r"""(?:data|body|payload|json|req\.body|request\.json)\[\s*["'](\w+)["']\s*\]"""),
    re.compile(r"""req\.body\.(\w+)"""),               # req.body.message (express)
    re.compile(r"""body\.(\w+)\b"""),                  # body.message (pydantic attr 접근)
]
# Pydantic 입력모델 첫 str 필드: class XIn(BaseModel):\n  message: str
_PYDANTIC_FIELD = re.compile(r"class\s+\w+\((?:[\w.]*BaseModel[\w.]*)\)\s*:\s*(.*?)(?=\nclass |\Z)", re.S)
_FIELD_DECL = re.compile(r"^\s*(\w+)\s*:\s*(?:str|Optional\[str\])", re.M)
# 응답 키 후보: return {"reply": ...} / jsonify({"reply":...}) / res.json({reply:...})
_RESP_KEY_PATS = [
    re.compile(r"""(?:return|jsonify\(|json\()\s*\{\s*["'](\w+)["']\s*:"""),
    re.compile(r"""res\.json\(\s*\{\s*(\w+)\s*:"""),   # express res.json({reply: ...})
]
# 라우트 경로: 데코레이터/메서드/stdlib path 비교
_ROUTE_PATS = [
    re.compile(r"""@\w+\.(?:post|route)\(\s*["'](/[\w/.-]*)["']"""),
    re.compile(r"""(?:app|router)\.post\(\s*["'](/[\w/.-]*)["']"""),
    re.compile(r"""path\s*==\s*["'](/[\w/.-]*)["']"""),   # stdlib http.server
]
# 실행 포트 후보(코드에서 감지 → URL 프리필용). 호스트는 런타임이라 감지 불가.
_PORT_PATS = [
    re.compile(r"""["']?PORT["']?\s*[,:=]\s*["']?(\d{2,5})"""),   # PORT default / "port": 8100
    re.compile(r"""\bport\s*=\s*(\d{2,5})"""),                    # port=8100 / run(port=8100)
    re.compile(r"""--port[=\s]+(\d{2,5})"""),                     # uvicorn --port 8000
    re.compile(r"""\.listen\(\s*(\d{2,5})"""),                    # express listen(3000)
]

# 흔한 이름 우선순위(높을수록 선호) — 오탐 줄이려 의미있는 이름 가중.
_REQ_PRIORITY = ["message", "prompt", "text", "input", "query", "question",
                 "content", "user_input", "msg", "q"]
_RESP_PRIORITY = ["reply", "response", "answer", "output", "text", "content",
                  "message", "result", "completion"]
_ROUTE_PRIORITY = ["/chat", "/api/chat", "/v1/chat/completions", "/message",
                   "/query", "/ask", "/completion", "/generate"]


def _best(cands, priority):
    """후보(빈도순 dict) 중 우선순위 리스트 먼저, 없으면 최빈값. 없으면 None."""
    if not cands:
        return None
    for p in priority:
        if p in cands:
            return p
    return max(cands, key=cands.get)


def detect_http_contract(sources):
    """레포 소스(dict{경로:코드} 또는 문자열)에서 HTTP 요청/응답 계약 감지.

    반환 dict: {request_field, response_path, route_path, body_template,
                confidence(0~1), evidence[]}  — 아무것도 못 찾으면 None(→ 폴백).
    """
    code = "\n".join(sources.values()) if isinstance(sources, dict) else (sources or "")
    if not code:
        return None

    req_counts, resp_counts, route_counts = {}, {}, {}
    for pat in _REQ_FIELD_PATS:
        for m in pat.findall(code):
            req_counts[m] = req_counts.get(m, 0) + 1
    for block in _PYDANTIC_FIELD.findall(code):       # Pydantic 첫 str 필드
        fm = _FIELD_DECL.search(block)
        if fm:
            req_counts[fm.group(1)] = req_counts.get(fm.group(1), 0) + 2  # 모델 필드는 가중
    for pat in _RESP_KEY_PATS:
        for m in pat.findall(code):
            resp_counts[m] = resp_counts.get(m, 0) + 1
    # 넓은 폴백: 아무 dict 리터럴 키든 응답 우선순위 이름이면 후보로(예: _send_json(200,{"reply":..}))
    for m in re.findall(r"""["'](\w+)["']\s*:""", code):
        if m in _RESP_PRIORITY:
            resp_counts[m] = resp_counts.get(m, 0) + 1
    for pat in _ROUTE_PATS:
        for m in pat.findall(code):
            route_counts[m] = route_counts.get(m, 0) + 1

    # 잡음 필드 제거(흔한 비-프롬프트 키)
    for noise in ("model", "stream", "role", "temperature", "status", "error",
                  "id", "object", "created", "usage", "choices", "messages"):
        req_counts.pop(noise, None)
        resp_counts.pop(noise, None)

    req = _best(req_counts, _REQ_PRIORITY)
    resp = _best(resp_counts, _RESP_PRIORITY)
    route = _best(route_counts, _ROUTE_PRIORITY)
    if not req and not resp:
        return None

    # 포트 감지(URL 프리필용). env 기본값 get("PORT","8100")은 실제 런타임 기본값이라
    # 가중치 크게(주석/예시 포트 오염 방지).
    port_counts = {}
    for m in re.findall(r"""\.get\(\s*["']PORT["']\s*,\s*["'](\d{2,5})["']""", code):
        port_counts[int(m)] = port_counts.get(int(m), 0) + 5
    for pat in _PORT_PATS:
        for m in pat.findall(code):
            p = int(m)
            if 1 <= p <= 65535:
                port_counts[p] = port_counts.get(p, 0) + 1
    port = max(port_counts, key=port_counts.get) if port_counts else None

    # confidence: 요청·응답 둘 다 + 우선순위 명중이면 높음.
    conf = 0.0
    conf += 0.4 if req else 0.0
    conf += 0.4 if resp else 0.0
    conf += 0.1 if (req in _REQ_PRIORITY) else 0.0
    conf += 0.1 if (resp in _RESP_PRIORITY) else 0.0

    body_template = '{"%s": "{{prompt}}"}' % (req or "message")
    return {
        "request_field": req, "response_path": resp or "reply",
        "route_path": route, "port": port, "body_template": body_template,
        "confidence": round(conf, 2),
        "evidence": {"request": req_counts, "response": resp_counts, "route": route_counts},
    }


# 레포에서 훑을 서버 후보 파일명(우선순위 순). 소수만 fetch.
_SERVER_FILE_HINTS = ("app.py", "main.py", "server.py", "api.py", "chat.py",
                      "server.js", "index.js", "app.js", "main.js")
_SERVER_DIR_HINTS = ("routes", "api", "src", "app", "server")


def _parse_repo(repo_url):
    """https://github.com/owner/repo(.git) → (owner, repo). 아니면 (None, None)."""
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", repo_url or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def fetch_repo_sources(repo_url, token=None, max_files=8, max_bytes=120_000):
    """GitHub 레포에서 서버 후보 소스 파일들을 fetch → dict{경로:코드}.

    공개 레포는 token 없이도 가능(rate-limit). 비공개/권한없음/오류 → 빈 dict(폴백).
    git tree(recursive)로 후보 파일 경로만 골라 contents API(raw)로 소수 fetch.
    지연 임포트(httpx)로 순수 감지 로직 테스트엔 네트워크 의존 없음.
    """
    import base64
    import httpx

    owner, repo = _parse_repo(repo_url)
    if not owner or not repo:
        return {}
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out = {}
    deadline = time.monotonic() + 15   # 감지 휴리스틱 전체 상한(워커 장시간 점유 방지)
    try:
        with httpx.Client(timeout=8, headers=headers) as client:
            info = client.get(f"https://api.github.com/repos/{owner}/{repo}")
            if info.status_code != 200:
                return {}
            branch = info.json().get("default_branch", "main")
            tree = client.get(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}",
                params={"recursive": "1"})
            if tree.status_code != 200:
                return {}
            paths = [n["path"] for n in tree.json().get("tree", []) if n.get("type") == "blob"]

            def score(p):
                base = p.rsplit("/", 1)[-1].lower()
                s = 0
                if base in _SERVER_FILE_HINTS:
                    s += 10 - _SERVER_FILE_HINTS.index(base)
                if any(("/" + d + "/") in ("/" + p.lower()) for d in _SERVER_DIR_HINTS):
                    s += 2
                if p.lower().endswith((".py", ".js", ".ts")):
                    s += 1
                return s

            for p in sorted([p for p in paths if score(p) > 0], key=score, reverse=True)[:max_files]:
                if time.monotonic() > deadline:   # 전체 deadline 초과 시 가진 것만 반환
                    break
                c = client.get(f"https://api.github.com/repos/{owner}/{repo}/contents/{p}",
                               params={"ref": branch})
                if c.status_code != 200:
                    continue
                j = c.json()
                if j.get("encoding") == "base64" and j.get("size", 0) <= max_bytes:
                    try:
                        out[p] = base64.b64decode(j["content"]).decode("utf-8", "ignore")
                    except Exception:  # noqa: BLE001
                        pass
    except Exception as e:  # noqa: BLE001 - 네트워크/파싱 실패 → 폴백
        log.warning("recon: 레포 fetch 실패(%s): %s", repo_url, e)
        return {}
    return out
