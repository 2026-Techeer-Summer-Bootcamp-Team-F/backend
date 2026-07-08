# 벡터DB 적재 — 실행 기록 (재현 매뉴얼)

> **목적**: 코퍼스 데이터/DB가 날아가도 **이 문서만 보고 그대로 재생성**할 수 있게, 무슨 소스를 어떻게 받아 어떻게 정제·적재했는지 상세 기록.
> 작성: 2026-07-08 · 대상: `app/backend/corpus.db` 의 `attack_cases`(공격 코퍼스), `atlas_techniques`(ATLAS 마스터).
> 계획 문서(왜 이 소스들인가)는 [벡터DB-적재계획.md](./벡터DB-적재계획.md) 참고. 이 문서는 **실제로 한 것**.

---

## 0. 한눈에 (파이프라인 전체)

```
[로컬 소스 3종]  jailbreak_prompts.csv / latest_jailbreaks_2026.csv / l1b3rt4s/*.mkd
[HF 소스 3종]    deepset-pi / safe-guard-pi / gandalf   (HTTP로 받아 hf_cache/*.jsonl 캐시)
        │
        ▼  corpus_ingest.py
  Step1 로드(소스별 어댑터) → Step1 필터(3단어 미만/초대형만 컷)
        → Step2a exact dedup(정규화+md5) → Step2b near dedup(토큰 자카드≥0.85, 교차)
        → Step3 적재(SQLite attack_cases, embedding=NULL)
        │
        ▼  (다음 단계, 아직 안 함)
  임베딩(로컬 MiniLM 384d) → pgvector + HNSW → verified(더미앱 발사)
```

**핵심 원칙**: 무거운 건 전부 로컬. 원문 프롬프트는 대화창에 안 뿌리고 스크립트가 파일→DB 직접 처리(안전필터 회피).

---

## 1. 실행 환경 · 제약 (중요)

- **파이썬**: `python3` = homebrew 3.14(있음), `/usr/bin/python3` = 시스템 3.9. 코드는 **stdlib만** 써서 둘 다 동작.
  - ⚠️ homebrew 파이썬은 pip/venv가 깨져 있어 **`datasets`·`sentence-transformers` 등 외부 라이브러리 설치 불가/위험**.
  - → 그래서 HF 데이터도 **라이브러리 없이 HTTP(datasets-server API)로 직접** 받음. 3.9 호환 위해 `datetime.now(timezone.utc)` 사용(utcnow 아님).
- **DB**: 지금은 **SQLite**(`corpus.db`, 의존성 0). pgvector(Postgres)는 임베딩 단계에서 Docker로 전환 예정.
- **네트워크**: HF datasets-server(`https://datasets-server.huggingface.co`)는 무인증으로 접근됨. 단 **429(rate limit)** 잘 걸림 → 쓰로틀 필수.

---

## 2. 스크립트 (무엇을 하는가)

| 파일 | 역할 | 네트워크 |
|---|---|---|
| `app/backend/atlas_ingest.py` | ATLAS 기법 **마스터**(`atlas_techniques`) 적재. 공식 mitre-atlas/atlas-data 기준 이름·전술 + 우리 한글 설명/완화책. | 없음(값 하드코딩) |
| `app/backend/fetch_hf.py` | HF 3소스를 **HTTP로 받아 `data/hf_cache/hf_prompts.jsonl` 캐시**로 저장. 소스별 어댑터로 표준레코드 변환. | **있음**(1회) |
| `app/backend/corpus_ingest.py` | 로컬 3소스 + HF 캐시를 **로드→필터→dedup→SQLite 적재**. 재현 핵심. | 없음(캐시는 로컬) |

**재현 순서**:
```bash
cd app/backend
python3 atlas_ingest.py      # ① ATLAS 마스터(9기법) 적재
python3 fetch_hf.py          # ② HF 3소스 → hf_cache/hf_prompts.jsonl (네트워크, 몇 분)
python3 corpus_ingest.py     # ③ 로컬3+HF 통합 적재 → corpus.db (오프라인, 수초)
```
> `hf_cache/hf_prompts.jsonl`이 이미 있으면 ②는 건너뛰어도 됨(오프라인 재적재 가능). ①은 ③의 ATLAS 조인 대상이라 먼저.

---

## 3. 소스별 상세 (무슨 데이터를 어떻게)

### 3-A. 로컬 소스 (이미 repo에 있음, `기획/poc/ai_redteam/data/`)

| 소스(source값) | 파일 | 접근/파싱 | 유형 매핑 | 비고 |
|---|---|---|---|---|
| `in-the-wild` | `jailbreak_prompts.csv` | csv, `jailbreak`컬럼 true 만 | jailbreak / `AML.T0054` | verazuo/TrustAIRLab. 원`source`는 tags 보존 |
| `latest-2026` | `latest_jailbreaks_2026.csv` | csv, 전 행(전부 탈옥) | jailbreak / `AML.T0054` | Pliny 계열 모델별. `model`·`technique`→tags |
| `l1b3rt4s` | `l1b3rt4s/*.mkd` (5파일) | 마크다운, `# ` / `## ` 헤딩마다 1건, 코드펜스 제거 | jailbreak / `AML.T0054` | 벤더·heading→tags |

- **분류 결정(중요)**: 이 3소스는 **전부 탈옥 코퍼스**라, 키워드 자동분류가 오히려 오분류(예: 롤플레이 탈옥을 data_leakage로)를 냈음. → **전부 `jailbreak`/`AML.T0054`로 통일**하고, 원 라벨(모델·기법·벤더·원source)은 **`tags`(JSON)에 보존**해 정보 무손실. 정밀 재분류는 임베딩 군집 단계로 이연.

### 3-B. HF 소스 (HTTP로 받아 캐시, `data/hf_cache/hf_prompts.jsonl`)

받는 방법 = **HF datasets-server `/rows` API** 페이지네이션(offset+length≤100), 쓰로틀 0.7초/페이지 + 429시 6·12·18초 백오프.

| 소스(source값) | HF 데이터셋 | split | 어댑터(필터·매핑) | 유형 매핑 |
|---|---|---|---|---|
| `deepset-pi` | `deepset/prompt-injections` | train+test | `label==1`(=injection)만. `text`→prompt | prompt_injection / `AML.T0051.000` |
| `safe-guard-pi` | `xTRam1/safe-guard-prompt-injection` | train+test | `label==1`만. `text`→prompt | prompt_injection / `AML.T0051.000` |
| `gandalf` | `Lakera/gandalf_ignore_instructions` | train+val+test | 전 행(전부 유출공격). `text`→prompt, `similarity`→tags | prompt_leakage / `AML.T0056` |

- **라벨 검증**: deepset `label=1`이 진짜 injection("Forget all previous tasks…" 등), `label=0`은 평범한 질문("Refugee crisis…")임을 실제 행을 받아 확인 후 필터 방향 확정(뒤집힘 방지).
- **왜 이 3개**: 지금 코퍼스가 **전부 jailbreak라 유형 다양성이 없어서**. injection·leakage를 채우는 게 목적.
- **제외한 것(과 이유)**:
  - `jayavibhav/prompt-injection`(261k) — safe-guard와 **같은 계보**(동일 벤치 예시) + 초대량 → 중복·대역폭으로 제외.
  - `JailbreakBench/JBB-Behaviors`(목표문 100), `Anthropic/hh-rlhf`(대화 선호쌍) — **공격 프롬프트가 아님**(목표문/대화) → 코퍼스 오염 방지 위해 제외.
  - `qualifire/...`, `allenai/wildjailbreak`, `walledai/AdvBench` — **HF 로그인 게이팅(401)** → 제외.

### 3-C. ATLAS 마스터 (`atlas_techniques`, 9기법)

- 공식 `raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml`에서 **직접 가져와** 이름/전술 교정(로컬 ATLAS.yaml은 deprecated).
- 교정 예: `AML.T0056` = **Extract LLM System Prompt**(옛 "Meta Prompt Extraction" 오타), `AML.T0053` = AI Agent Tool Invocation.
- **T0062(환각)·T0029(DoS) 공식 존재 확인** — 로컬 마스터에 없던 것뿐(A2 이슈 해소).
- PK 컬럼명 = **`id`**(문자열, 예 `AML.T0054`). `attack_cases.atlas_technique_id`가 이걸 참조(조인 고아 0 검증).

---

## 4. 정제·dedup 상세 (질을 좌우하는 단계)

- **필터**(`_ok`): `3단어 미만`(진짜 빈 것/1~2단어 조각)과 `12,000자 초과`(사고성 초대형)만 컷. **길이로는 안 자름** — 짧아도 살리고, 실제 성공여부는 나중에 `verified`(더미앱 발사)로 가림.
  - (이전엔 15자 미만 컷이었으나, "짧아도 성공한 케이스면 써야 한다"는 판단으로 완화.)
- **정규화**(`normalize`): 소문자화 + 공백 통일 + 문장부호 제거 → 표기만 다른 중복을 잡기 위함.
- **Step2a exact dedup**: 정규화 텍스트의 md5 해시로 완전중복 제거.
- **Step2b near dedup**: 정규화 토큰 **집합의 자카드 유사도 ≥ 0.85**면 유사중복으로 보고 뒤엣것 제거. **모든 소스를 합친 뒤 교차**로 수행(소스 간 중복도 제거).
  - 관측 예: `l1b3rt4s` 56건 중 45건이 다른 두 소스와 **완전중복**, 5건이 `latest-2026`(1,500자로 잘린 동일 프롬프트)과 근접중복 → l1b3rt4s 고유는 6건. (버그 아님 = Pliny 프롬프트가 널리 퍼져 있음)

---

## 5. 결과 수치 (2026-07-08 최종 — 임베딩 직전 완성본)

**파이프라인 전체:** raw **5,915** → 필터 통과 5,883 → exact dedup 5,184(완전중복 -699) → near dedup **4,867**(유사중복 -317). 총 -17.3% 압축. ATLAS 조인 고아 **0**.

**소스별 적재(6소스):**

| source | 건수 | 유형 | 비고 |
|---|---:|---|---|
| in-the-wild | 1,167 | jailbreak | verazuo |
| safe-guard-pi | 2,419 | prompt_injection | xTRam1 (label==1) |
| gandalf | 979 | prompt_leakage | Lakera |
| deepset-pi | 245 | prompt_injection | deepset (label==1) |
| latest-2026 | 51 | jailbreak | Pliny 최신 |
| l1b3rt4s | 6 | jailbreak | Pliny(나머지 중복) |
| **합계** | **4,867** | | |

**유형별(← 이번 라운드 성과 = 유형 다양성 확보):**
- `prompt_injection` **2,664** / `jailbreak` **1,224** / `prompt_leakage` **979**
- 이전(로컬만)엔 전부 jailbreak(1,224)였는데, HF injection/leakage 추가로 **3유형 분포**가 됨. → 유형 필터·히트맵 데모 가능해짐.

> HF 캐시는 4,298건 기록됐으나 실제 파일엔 gandalf validation split이 429로 죽기 직전 쓴 ~90행이 더 있어 ingest raw는 그만큼 많음(정상 데이터, 요약 카운트에만 누락). 최종 dedup 후 gandalf 979.

---

## 5-1. 임베딩 완료 (2026-07-08)

- **21,219 / 21,219 전부 384d 임베딩** 채움(`embedding` 컬럼, JSON 배열). 8유형 전부.
- **방법**: 호스트 pip 깨짐 → **Docker 컨테이너**(`python:3.11-slim`)에서 **fastembed**(onnxruntime, torch 불필요)로 `sentence-transformers/all-MiniLM-L6-v2`(384d) 계산. `embed.py`, resumable(`embedding IS NULL`만 → 증분 가능, 모델 바꿀 때만 전체 재계산).
- **검증**: DoS 프롬프트로 유사도검색 → Top4 전부 DoS(코사인 0.77~0.64), Top10 중 6 동일유형 → **의미 군집·벡터검색 작동 확인**(차별점 실증).
- **품질 감사**(임베딩 전): 완전중복 0, jayavibhav 근접중복 0%(샘플), 템플릿 반복 4%, 비영어 0%, median 349자 → 질 양호·중복 낮음.

## 6. 아직 안 한 것 (다음 단계)

1. ~~임베딩~~ ✅ 완료(§5-1). 다음은 **SQLite → pgvector 이관** + HNSW 인덱스(엔진 retrieve 최적화). PoC 규모(21k)는 브루트포스 코사인으로도 충분 → 이관은 최적화.
2. **pgvector 이관**: SQLite → Postgres(pgvector) + HNSW(cosine) 인덱스. `docker-compose.yml`에 pgvector 이미 있음.
3. **verified**: 자체 더미앱(`POST /dummy/acmebank/chat`)에 실제 발사해 통과분만 `verified=1`.
4. **부족 유형 보강**: indirect injection(BIPIA/InjecAgent, GitHub json), tool abuse, PII → 계획서 §2-5. hallucination(T0062)·DoS(T0029)는 **자체 템플릿**(데이터셋 없음).
5. **정본 스키마 병합**: 지금 `attack_cases`는 관통용 간이본. 정본(ERD `worked_on`, `updated_at`/`deleted_at`)과 합쳐야 함.

---

## 7. 주의 · 함정 (다시 할 때 조심)

- **원문 프롬프트를 응답/로그에 그대로 출력하지 말 것** → 안전필터에 걸려 API 에러 남. 개수·통계만 보고.
- **HF API 429**: 쓰로틀(0.7s) + 백오프 필수. 탐색과 대량 페이징을 연달아 하면 걸림.
- **라벨 뒤집힘**: 분류셋(`label`)은 반드시 실제 행 샘플로 1=공격인지 확인 후 필터.
- **dedup 방향**: 먼저 로드된 소스가 남고 뒤가 지워짐. "고유 기여"를 보려면 소스 로드 순서 기억.
- **SQLite `atlas_techniques` PK는 `id`** (technique_id 아님). 조인 시 주의.

> 관련: [벡터DB-적재계획.md](./벡터DB-적재계획.md)(왜), [ERD-완전정리.md](./ERD-완전정리.md)(정본 스키마), [../트러블슈팅.md](../트러블슈팅.md) #14.
