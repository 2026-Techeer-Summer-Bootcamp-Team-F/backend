# AI 레드팀 — API 명세 (Swagger/OpenAPI 기준)

> **ERD 최종본([ERD-완전정리.md](./ERD-완전정리.md)) + 와이어프레임([assets/wireframe.png](./assets/wireframe.png)) 기준 API 설계.**
> FastAPI로 구현하면 이 명세 그대로 `/docs`(Swagger UI)에 자동 노출됨.
>
> - **Base URL(PoC)**: `http://localhost:8000`
> - **인증**: GitHub OAuth → JWT(Bearer). 보호 API(🔒)는 `Authorization: Bearer <jwt>` 필요.
> - **소유확인**: 별도 인증 없음 — **GitHub 로그인 + 리포 접근**으로 갈음(ERD에서 verify 컬럼 제거됨).
> - **공통 에러**: `{ "detail": "<메시지>" }` + 상태코드(400/401/403/404/409/422/500).
> - **PoC 모드**: `AUTH_MODE=mock`이면 `POST /auth/dev-login`으로 실제 GitHub 없이 토큰 발급.

---

## 📱 화면 ↔ API 매핑 (와이어프레임 기준)

와이어프레임 화면 순서: **랜딩(SK쉴더스식) → 로그인(GitHub) → Import Git Repository(Vercel식) → 동의+액터구성 → AI Red Teaming Analysis(공격유형 선택+실시간) → 결과 대시보드(통계+히트맵+Findings)**

| 화면 (와이어프레임) | 쓰는 API |
|---|---|
| ① 랜딩 (히어로 "안녕을 지키는 기술" + 보안뉴스 카드 3개) | (정적) + 옵션 `GET /feed/security-news` · `GET /atlas`(기법 카드) |
| ② 로그인 (**"깃허브 로그인 정도만"** + Google 옵션) | `GET /auth/github/login` · `/callback` · `GET /auth/me` |
| ③ Import Git Repository (Vercel식 리포 목록 + Import 버튼) | `GET /github/repos` · `POST /projects` |
| ④ 동의 페이지 + 액터 구성 정보 입력 | `POST /projects` · `POST /projects/{id}/recon` |
| 프로젝트 선택 대시보드 | `GET /projects` · `GET /projects/{id}` · `DELETE /projects/{id}` |
| ⑤ **AI Red Teaming Analysis** (Attack Type 체크박스 13개 + Target Model 드롭다운 + Start Scan + Live Analysis Log + Summary) | `GET /attack-types` · `POST /scans` · `GET /scans/{id}/stream`(SSE) · `POST /scans/{id}/cancel` |
| ⑥ 결과 대시보드 (통계 숫자 4개 + MITRE ATLAS 히트맵 + Top Findings) | `GET /scans/{id}/report` · `/heatmap` · `/findings` · `/objectives/{id}/tree` · `/attempts/{id}` · `/scans/{id}/events` |

> 참고 UX 노트(와이어프레임 주석): "분석/결과 메뉴는 **로그인 안 됐으면 로그인창으로 렌더링**" · "온보딩 없이 바로 로그인창→대시보드로?" · "보안 뉴스 피드는 **부가기능**".

---

## 1. Auth (인증)

### `GET /auth/github/login`
GitHub OAuth 시작. `state`(CSRF) 세팅 후 GitHub 인가 URL 반환/리다이렉트.
- **200**: `{ "authorize_url": "https://github.com/login/oauth/authorize?..." }`

### `GET /auth/github/callback`
| 쿼리 | 타입 | 설명 |
|---|---|---|
| code | string | GitHub 인가 코드 |
| state | string | CSRF 검증 |

- 처리: code→access_token 교환 → GitHub `/user` 조회 → `users` upsert(github_id 기준) → JWT 발급.
- **200**: `{ "access_token": "<jwt>", "token_type": "bearer", "user": {User} }`
- **401**: code/state 무효.

### `POST /auth/dev-login` *(PoC 전용, AUTH_MODE=mock)*
- 요청: `{ "github_name": "demo-user", "name": "데모" }`
- **200**: `{ "access_token": "<jwt>", "token_type": "bearer", "user": {User} }`
- **403**: mock 모드 아님.

### `GET /auth/me` 🔒
- **200**: `User`
- **401**: 토큰 없음/만료.

### `POST /auth/logout` 🔒
로그아웃 — 서버측 JWT 무효화(세션 종료). 프론트는 저장 토큰 삭제 + 이 호출.
- **204**: 성공(본문 없음)

### (옵션) `GET /auth/google/login`, `GET /auth/google/callback`
와이어프레임의 Google 로그인. GitHub와 동일 패턴. (PoC 후순위)

**`User` 스키마** (users 테이블):
```json
{ "user_id": 1, "github_id": "583231", "github_name": "gangminseo",
  "name": "강민서", "created_at": "2026-07-06T14:30:00Z" }
```

---

## 2. GitHub Repos (Import Git Repository 화면)

### `GET /github/repos` 🔒
로그인 사용자의 GitHub 리포 목록 (Vercel식 Import 화면용). `access_token_enc`로 GitHub API 호출.
- 쿼리: `?q=검색어&page=1`
- **200**:
```json
[ { "full_name": "gangminseo/bank-bot", "html_url": "https://github.com/...",
    "description": "고객 챗봇", "private": false, "updated_at": "2026-07-01T..." } ]
```

---

## 3. Projects (분석프로젝트 = target_projects)

### `POST /projects` 🔒
대상 앱 등록. (Import한 리포 또는 직접 입력)
- 요청:
```json
{
  "project_name": "AcmeBank 고객봇",
  "actor_type": "http",
  "config": {
    "url": "http://localhost:8000/dummy/acmebank/chat",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "body_template": "{\"message\": \"{{prompt}}\"}",
    "response_path": "reply",
    "max_retries": 4
  },
  "purpose": "고객지원 챗봇",
  "system_prompt": null,
  "repo_url": "https://github.com/acme/bank-bot"
}
```
- **201**: `Project` (정찰 필드 model/defences/tools/rag_sources는 아직 null → recon으로 채움)
- **422**: 필수 필드 누락.

### `GET /projects` 🔒
- **200**: `[Project, ...]` (본인 소유만)

### `GET /projects/{id}` 🔒
- **200**: `Project` / **403**: 타인 / **404**: 없음

### `POST /projects/{id}/recon` 🔒
정찰 실행(리포분석 + 블랙박스 프로빙) → `target_projects`의 model/defences/tools/rag_sources 채움.
- **200**:
```json
{ "model": "gpt-4o-mini", "defences": ["moderation"], "tools": ["send_email"],
  "rag_sources": ["faq.pdf"], "source": "repo" }
```

### `PATCH /projects/{id}` 🔒
등록한 프로젝트 수정(액터 config·용도·시스템프롬프트 등). 수정할 필드만 보냄.
- 요청(부분): `{ "project_name"?, "config"?, "purpose"?, "system_prompt"?, "repo_url"? }`
- **200**: `Project` / **403**: 타인 / **404**: 없음

### `DELETE /projects/{id}` 🔒 → **204** (soft-delete)

**`Project` 스키마** (target_projects):
```json
{
  "target_id": 3, "user_id": 1, "project_name": "AcmeBank 고객봇",
  "actor_type": "http", "config": { "...": "..." },
  "purpose": "고객지원 챗봇", "system_prompt": null,
  "repo_url": "https://github.com/acme/bank-bot",
  "model": "gpt-4o-mini", "defences": ["moderation"],
  "tools": ["send_email"], "rag_sources": ["faq.pdf"],
  "created_at": "2026-07-06T15:00:00Z"
}
```

---

## 3-1. Attack Types (공격 유형 목록 — Analysis 화면 좌측 체크박스)

### `GET /attack-types` 🔒
와이어프레임 좌측 "Attack Type" 체크박스 13개. 사용자가 고른 걸 스캔 config에 넣음.
각 유형은 ATLAS 기법 + objectives.category에 매핑됨.
- **200**:
```json
[
  {"key":"direct_prompt_injection","label":"Direct Prompt Injection","atlas":"AML.T0051.000","category":"prompt_injection"},
  {"key":"indirect_prompt_injection","label":"Indirect Prompt Injection","atlas":"AML.T0051.001","category":"prompt_injection"},
  {"key":"jailbreak","label":"Jailbreak","atlas":"AML.T0054","category":"jailbreak"},
  {"key":"system_prompt_extraction","label":"System Prompt Extraction","atlas":"AML.T0056","category":"prompt_leakage"},
  {"key":"prompt_leakage","label":"Prompt Leakage","atlas":"AML.T0056","category":"prompt_leakage"},
  {"key":"data_leakage","label":"Data Leakage","atlas":"AML.T0057","category":"data_leakage"},
  {"key":"pii_leakage","label":"PII Leakage","atlas":"AML.T0057","category":"pii"},
  {"key":"tool_function_abuse","label":"Tool/Function Abuse","atlas":"AML.T0053","category":"tool_abuse"},
  {"key":"tool_manipulation","label":"Tool Manipulation","atlas":"AML.T0053","category":"tool_abuse"},
  {"key":"roleplay_persona","label":"Side-play / Persona Attack","atlas":"AML.T0054","category":"jailbreak"},
  {"key":"encoding_obfuscation","label":"Encoding & Obfuscation","atlas":"AML.T0051.000","category":"prompt_injection"},
  {"key":"hallucination_induction","label":"Hallucination Induction","atlas":"AML.T0062","category":"misinformation"},
  {"key":"dos","label":"Denial of Service (DoS)","atlas":"AML.T0029","category":"dos"}
]
```

---

## 4. Scans (스캔 실행 + 실시간) — AI Red Teaming Analysis 화면

### `POST /scans` 🔒
스캔 트리거(백그라운드 실행). "Start Scan" 버튼. 즉시 반환.
- 요청: (Analysis 화면에서 고른 **공격유형 + 타겟모델**)
```json
{
  "target_id": 3,
  "config": {
    "attack_types": ["direct_prompt_injection", "jailbreak", "pii_leakage"],
    "target_model": "gpt-4o",
    "population_size": 8,
    "max_generations": 5
  }
}
```
| config 필드 | 뜻 | 값 |
|---|---|---|
| attack_types | 고른 공격 유형(체크박스) → objectives 생성 | `GET /attack-types`의 key 배열 |
| target_model | 타겟 모델 드롭다운 | `gpt-4o`/`claude`/`current`(정찰값 사용)/`local` |
| population_size | 한 세대 공격 수 | `8` |
| max_generations | 최대 세대 | `5` |

- 처리: 고른 attack_types 각각을 `objectives`(atlas 기법) 레코드로 **변환 생성** → 진화 스캔 시작. **`scans.config`엔 요청 그대로(`attack_types`) 저장**하고, `objectives`는 별도 테이블 레코드(→ `GET /scans/{id}` 응답의 `objectives`).
> ⚠️ **D1**: 여러 attack_type이 같은 ATLAS로 겹침(13유형→ATLAS 8개, 예: jailbreak·roleplay_persona→T0054, data_leakage·pii_leakage→T0057) → `objectives` 생성 시 **atlas 기준 dedup** 권장(히트맵 칸 중복 방지).
- **202**: `{ "scan_id": 12, "status": "pending" }`

### `GET /scans` 🔒 → `[Scan, ...]` (본인 프로젝트의 스캔)

### `GET /scans/{id}` 🔒
- **200**: `Scan` + `{ "objectives": [Objective], "progress": {...} }`

### `GET /scans/{id}/stream?token=<jwt>` 🔒 *(SSE)* — Live Analysis Log / Current Attack / Summary
스캔 실시간 진행. `text/event-stream`. `EventSource`가 헤더를 못 실으므로 **JWT를 `?token=` 쿼리로**.
각 이벤트에 `id:`(=scan_events_id) 포함 → 재연결 시 `Last-Event-ID`로 놓친 구간 재생.
- 화면 매핑: `log`→**Live Analysis Log**, `progress`→**Progress바 + Current Attack + Summary**, `finding`→Top Findings, `done`→완료.
```
id: 47
event: log
data: {"msg":"Loading Attack Modules...","level":"info"}

id: 48
event: progress
data: {"generation":2,"evaluated":14,"best_score":0.7,"phase":"mutate",
       "current_attack":{"name":"Prompt Injection","atlas":"AML.T0051","status":"testing"},
       "summary":{"completed":8,"total":13,"success":5,"failed":3,"running":1}}

id: 49
event: attempt
data: {"objective_id":3,"generation":2,"verdict":"safe","score":0.4,"parent_attempt_id":7}

id: 50
event: finding
data: {"objective_id":3,"atlas":"AML.T0057","severity":"high","canary":"FLAG..."}

id: 51
event: done
data: {"status":"done","breached":2,"total_objectives":13}
```
- `log` = Live Analysis Log 한 줄(Loading Attack Modules / Sending Prompt / Response Received...).
- `progress.summary` = 우측 Summary 패널(Completed 8/13, Success 5, Failed 3, Running 1).
- `progress.current_attack` = "Current Attack: Prompt Injection / AML.T0051 / Testing".
- **401**: 토큰 없음.

### `POST /scans/{id}/cancel` 🔒 → `{ "status": "failed", "stop_reason": "cancelled" }`

**`Scan` 스키마** (scans):
```json
{ "scan_id": 12, "target_id": 3, "status": "running",
  "config": {"attack_types":["direct_prompt_injection","jailbreak"],"target_model":"gpt-4o","population_size":8,"max_generations":5},
  "progress": {"generation":2,"evaluated":14,"best_score":0.7,"phase":"mutate"},
  "started_at": "2026-07-06T15:00:00Z", "finished_at": null }
```

---

## 5. Results / Dashboard (대시보드 화면)

### `GET /scans/{id}/report` 🔒
스캔 통계 요약(대시보드 상단 통계 숫자 4개 + 요약 카드). 없으면 즉석 생성.
- **200** (scan_reports + 대시보드 표시용 파생값):
```json
{ "report_id": 8, "scan_id": 12,
  "total_objectives": 13, "breached_count": 2,   // breached_count = 뚫린 "목표" 수
  "coverage_pct": 100.00, "severity_counts": {"critical":1,"high":2,"medium":0},
  "risk_score": 90,
  "stats": {
    "total_attempts": 121,      // 총 공격 시도 수
    "breached_attempts": 41,    // 뚫린 "시도" 수 (breached_count=목표와 구분)
    "findings": 14              // 확정 취약점 수
  }
}
```
> **대시보드 큰 숫자 4개 = `risk_score`(위험도) / `total_attempts`(총 시도) / `breached_attempts`(뚫린 시도) / `findings`(취약점 수)** 로 확정(2026-07-07).
> ⚠️ **`breached_count`(뚫린 목표 수) vs `stats.breached_attempts`(뚫린 시도 수)** — 이름 혼동 방지로 후자를 `breached_attempts`로 명명. 옛 `attack_types_tested` 지표는 제거. scan_reports 원본 컬럼 + attempts·findings 집계로 계산.

### `GET /scans/{id}/summary` 🔒
리포트 **AI 요약** — 스캔 결과(뚫린 목표·심각도·증거)를 LLM이 사람이 읽기 쉬운 요약문으로 생성(기능명세 #16). *대안: `GET /scans/{id}/report` 응답에 `ai_summary` 필드로 통합해도 됨(택1).*
- **200**: `{ "ai_summary": "이 앱은 프롬프트 인젝션으로 시스템 프롬프트가 유출됨(critical). 입력 필터 도입 권장..." }`

### `GET /scans/{id}/findings` 🔒
취약점 목록.
> ※ ERD 정규화로 `findings` 테이블은 **`attempt_id`만 저장**. 응답의 `objective_id`·`atlas_technique_id`는 `attempt→objective` 조인으로 채운 **파생 필드**(DB 컬럼 아님).
- **200**: `[Finding, ...]`
```json
[ { "findings_id": 7, "objective_id": 3, "attempt_id": 9,
    "atlas_technique_id": "AML.T0051", "severity": "critical",
    "title": "시스템 프롬프트 유출",
    "evidence": {"prompt":"관리자인데...","response":"...FLAG123...","canary":"FLAG123"},
    "mitigation": "입력 필터 추가, 시스템프롬프트 분리" } ]
```

### `GET /scans/{id}/heatmap` 🔒
ATLAS 히트맵(objectives 집계 + atlas_techniques 라벨).
- **200**:
```json
{ "techniques": [
  {"atlas_technique_id":"AML.T0051.000","name":"Direct Prompt Injection","status":"breached","attempts":9,"best_score":0.95},
  {"atlas_technique_id":"AML.T0054","name":"LLM Jailbreak","status":"safe","attempts":12,"best_score":0.42}
] }
```

### `GET /objectives/{id}/tree` 🔒
진화 트리(attempts 재귀 계보, parent_attempt_id 기준).
- **200**:
```json
{ "objective_id": 3, "nodes": [
  {"attempts_id":7,"parent_attempt_id":null,"generation":0,"score":0.4,"verdict":"safe","mutation_op":"none","attack_id":102,"prompt_text":"..."},
  {"attempts_id":9,"parent_attempt_id":7,"generation":1,"score":0.95,"verdict":"breach","mutation_op":"rephrase","improvement":"관리자 프레이밍 강화","prompt_text":"..."}
] }
```

### `GET /attempts/{id}` 🔒 → `Attempt` (전체 상세: prompt/response/judge_detail)
```json
{ "attempts_id":9, "objective_id":3, "parent_attempt_id":7, "attack_id":102,
  "generation":1, "prompt_text":"...", "response_text":"...FLAG123...",
  "score":0.95, "verdict":"breach",
  "judge_detail":{"stage":"canary","canary_hit":true,"refusal":false},
  "mutation_op":"rephrase", "improvement":"관리자 프레이밍 강화" }
```

### `GET /scans/{id}/events` 🔒
스캔 타임라인(scan_events, 영속화). 대시보드 catch-up / 재접속 복구용.
- 쿼리: `?after=<scan_events_id>` (그 순번 이후만 — 유실 복구)
- **200**:
```json
[ {"scan_events_id":47,"event_type":"progress","payload":{...},"created_at":"..."},
  {"scan_events_id":48,"event_type":"attempt","payload":{...},"created_at":"..."} ]
```

---

## 6. ATLAS 기법 (히트맵/기법 사전)

### `GET /atlas` 🔒
ATLAS 기법 마스터(atlas_techniques). 히트맵 라벨·기법 카드.
- **200**: `[{ "atlas_techniques_id":"AML.T0051.000", "name":"Direct Prompt Injection", "tactic":"...", "category":"prompt_injection", "description":"...", "mitigation":"..." }]`

---

## 7. Attack Corpus (공격 코퍼스 = attack_cases)

### `GET /corpus/stats` 🔒
- **200**: `{ "total": 1405, "by_type": {"jailbreak":900,"prompt_injection":...}, "verified": 210, "sources": ["jailbreak_llms","L1B3RT4S","spml"] }`

### `GET /corpus/search` 🔒
- 쿼리: `?attack_type=jailbreak&atlas=AML.T0054&verified=true&limit=20`
- **200**: `[AttackCase, ...]` (embedding 필드는 축약/제외)
```json
[ { "attack_id":102, "prompt_text":"You are DAN...", "attack_type":"jailbreak",
    "atlas_technique_id":"AML.T0054", "source":"jailbreak_llms",
    "worked_on":["gpt-4o"], "verified":true, "tags":["roleplay"] } ]
```

---

## 8. Health

### `GET /health` → `{ "status":"ok", "auth_mode":"mock", "db":"sqlite" }`

---

## 9. 상태코드 규약

| 코드 | 의미 |
|---|---|
| 200 | 조회/처리 성공 |
| 201 | 리소스 생성(프로젝트 등록) |
| 202 | 비동기 작업 수락(스캔 트리거) |
| 204 | 삭제 성공(본문 없음) |
| 401 | 미인증(토큰 없음/만료) |
| 403 | 권한 없음(타인 리소스) |
| 404 | 리소스 없음 |
| 409 | 상태 충돌 |
| 422 | 요청 검증 실패(FastAPI 기본) |

---

## 10. ERD 최종본 대비 변경점 (구 API.md 대비)

- `targets` → **`projects`**(엔드포인트) / `target_projects`(테이블). 필드 `name`→`project_name`.
- **소유확인 API 삭제**(`/targets/{id}/verify`) — GitHub 로그인으로 갈음.
- **`GET /github/repos` 신설** — Vercel식 Import Git Repository 화면용.
- 정찰이 프로젝트에 통합 → `POST /projects/{id}/recon` 결과가 프로젝트 필드(model/defences/tools/rag_sources) 갱신.
- 스캔 config에서 `model` 제거(엔진=클로드 고정).
- FK/PK 이름 ERD 최종본과 일치: `target_id`, `scan_id`, `objective_id`, `attempts_id`, `attack_id`, `findings_id`, `report_id`, `scan_events_id`.
- SSE 이벤트에 `id:`(=scan_events_id) + `?after=` 쿼리 = 순번 기반 유실 복구.
- **(2026-07-08 보강)** 누락 엔드포인트 추가: `POST /auth/logout`(§1)·`PATCH /projects/{id}`(§3)·`GET /scans/{id}/summary`(AI요약, §5). 스캔 config 예시를 `attack_types` 기준으로 통일(내부 모순 제거). 더미앱·뉴스피드는 **부록 A**(제품 API 아님)로 강등. 노션 "💽 API 명세" DB와 동기화.

---

## 부록 A. 데모·부가 엔드포인트 (⚠️ 제품 API 아님)

> 아래는 **우리 제품이 사용자에게 제공하는 API가 아님.** 프론트가 호출하지 않으며 제품 API 계약에서 제외한다. PoC를 자체 완결로 돌리기 위한 **데모 픽스처 / 부가기능**일 뿐. (FastAPI Swagger `/docs`엔 자동 노출되지만 계약은 아님.)

### A-1. 데모용 더미 대상 (공격 연습용 표적)
실제 서비스의 공격 대상 = **사용자(고객사) 앱**. 데모에선 그 대상을 대신할 **가짜 표적**을 우리가 직접 띄운다(→ `공격시나리오-설계.md`: "더미앱을 고객사 앱처럼 구성").
- **`POST /dummy/acmebank/chat`** *(인증 불필요, 격리 데모)* — 요청 `{ "message": "<공격 프롬프트>" }` → **200** `{ "reply": "<챗봇 응답>" }`. 특정 인젝션/롤플레이에 카나리 `FLAG{...}` 유출 → 스캔이 탐지.

### A-2. 보안 뉴스 피드 (랜딩 부가기능 — 옵션)
- **`GET /feed/security-news`** *(인증 불필요, 옵션)* — 랜딩 하단 보안 뉴스/기법 카드 3개. "부가기능" → 후순위. **200** `[{ "title":"...", "tag":"Research & Technique", "url":"...", "date":"..." }]`

---

> 관련: [ERD-완전정리.md](./ERD-완전정리.md) · [DESIGN-REF.md](./DESIGN-REF.md) · [ARCHITECTURE.md](./ARCHITECTURE.md) · (구) [API.md](./API.md)
