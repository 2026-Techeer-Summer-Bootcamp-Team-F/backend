# 벡터 DB 적재 계획 (pgvector 코퍼스 구축)

> 목표: **검증 공격 코퍼스**를 여러 소스에서 수집 → 통일 스키마 → 임베딩 → pgvector 적재. (우리 최대 차별점의 데이터 토대)
> 작성: 2026-07-07 · 근거: 웹 리서치(AWS/HF/GitHub, 하단 출처).

---

## 0. 큰 그림 (순서)
```
Step 0. 로컬 Docker pgvector 띄우기 (무료·무제한) ← 적재·개발은 전부 여기서
Step 1. 데이터 소스 수집 (다운로드 스크립트)
Step 2. 통일 스키마 매핑 + 정제 + dedup
Step 3. 임베딩(로컬 MiniLM 384d) + pgvector 적재 + HNSW
Step 4. (배포/시연) RDS free tier or Neon 로 이관
```
**핵심 원칙(비용): 무거운 적재·임베딩·인덱싱은 로컬 Docker(무료)에서 하고, 클라우드(RDS)엔 결과만 올린다.** 유료 RDS에 대량 임베딩·쿼리를 돌리면 비싸짐.

---

## 1. DB 띄우기 (저비용)

### 1-1. 개발·적재 = 로컬 Docker pgvector (무료)
- 이미 `docker-compose.yml`에 `pgvector/pgvector:pg16` 있음. `docker compose up` 하면 끝.
- 적재 스크립트가 여기 붙어서 임베딩·INSERT·HNSW 다 로컬에서. **비용 0, 대역폭 0, 빠름.**

### 1-2. 배포·시연 = 저비용 관리형 (택1)
| 옵션 | 무료 한도 | 특징 | 우리 판단 |
|---|---|---|---|
| **AWS RDS** (아키텍처 기준) | **신규계정 12개월**: db.t4g.micro 750h/월 + gp3 20GB + backup 20GB | 12개월 후 ~$14/월. **20GB라 대량 코퍼스 여유** | 신규 AWS 계정이면 ⭐(넉넉) |
| **Neon** | 0.5GB/프로젝트, 100 compute-h, **scale-to-zero(안 쓰면 과금 0)** | 작지만 미사용 과금 0 = 시연 최적. pgvector(PG15.2+) | 코퍼스 작으면(≤0.5GB) 좋음 |
| **Supabase** | 500MB, pgvector 무료, **7일 미사용 시 pause** | 대시보드 편함 | 500MB 제한 |

- **결론**: 
  - 신규 AWS 계정 있으면 → **RDS free tier**(20GB 여유, 아키텍처와 일치, 발표에 "AWS RDS" 말 가능).
  - 계정 없거나 코퍼스 작으면 → **Neon**(scale-to-zero, 돈 0에 가깝게).

### 1-3. RDS 저비용 설정 (돈 최소)
- 엔진: **PostgreSQL 15.2+** (pgvector는 무료 확장, `CREATE EXTENSION vector;`)
- 인스턴스: **db.t4g.micro**(ARM, 2vCPU/1GB, free tier 대상) — Single-AZ
- 스토리지: **gp3 20GB** (free tier 한도)
- **끄기**(추가 과금): Multi-AZ, Performance Insights, Enhanced Monitoring, 자동 스토리지 확장 상한 낮게
- Backup retention: 1일(or free 20GB 내)
- ⚠️ **db.t4g.micro 1GB RAM은 대량 HNSW 인덱스 빌드에 빠듯** → 그래서 §0대로 **적재·인덱싱은 로컬**, RDS엔 `pg_dump`로 넣거나 결과만.
- 미사용 시 인스턴스 **stop**(RDS 최대 7일 자동중지 후 자동재시작 주의 → cron으로 재중지).

---

## 2. 데이터 소스 (싹 수집)

### 2-1. 이미 확보 (`기획/poc/ai_redteam/data/`)
- `jailbreak_prompts.csv` — verazuo/jailbreak_llms (1,405, in-the-wild/DAN)
- `ATLAS.yaml` — MITRE ATLAS (432 기법, 라벨 마스터)
- `l1b3rt4s/*.mkd` — Pliny(elder-plinius) 모델별 탈옥
- `latest_jailbreaks_2026.csv`

### 2-2. 추가 수집 대상 (우선순위)
| 소스 | 규모 | 유형 | 수집 |
|---|---|---|---|
| ⭐ **Necent/llm-jailbreak-prompt-injection-dataset** (HF) | **30+ 데이터셋 통합** | jailbreak·injection·harmful·toxicity·agentic | `datasets.load_dataset` — 이거 하나로 대량 |
| **TrustAIRLab/in-the-wild-jailbreak-prompts** (HF) | 대량(최신) | in-the-wild | verazuo의 HF 최신본 |
| **AdvBench** (Zou 2023) | 520 behaviors + strings | harmful behaviors | GitHub llm-attacks |
| **HarmBench** (Mazeika 2024) | 표준 | 레드팀 표준 프레임 | HF/GitHub |
| **JailbreakBench / JBB-Behaviors** (NeurIPS'24) | 100 behaviors | jailbreak 벤치 | github.com/JailbreakBench |
| **JailBreakV-28K** | 28k | 멀티모달 탈옥 | HF |
| **HackAPrompt** (HF) | 600k+ | 인젝션("PWNED") | HF (⚠️라벨 약함, 필터링 필요) |
| **SPML** | - | 시스템프롬프트 인젝션 | Necent 통합본에 포함 |
| **Lakera Gandalf** | 성공 인젝션 | 게임 유래 실전 성공 | HF/Lakera |
| **SALAD-Bench** (attack-enhanced) | - | 증강 공격 | HF |
| **Qualifire Prompt Injections Benchmark** | 5,000 | 인젝션 | HF |
| **rogue-security/prompt-injections-benchmark** (HF) | - | 인젝션 | HF |
| **Mindgard/evaded-...-samples** (HF) | - | 우회형 | HF |
| **garak payloads** (NVIDIA) | 번들 | probe별 payload | GitHub `garak/data/` |
| **CySecBench** | - | 사이버보안 특화 | arXiv/GitHub |

**더 찾을 인덱스(큐레이션 리스트)**: `byoniq/AI-Redteaming`, `ant-research/awesome-mllm-guardrails`, `Libr-AI/OpenRedTeaming` — 여기서 신규 소스 계속 발굴.

### 2-3. 수집 방법
- **HuggingFace**: `pip install datasets` → `load_dataset("Necent/...")` 또는 parquet/csv 직접 다운. (대용량은 streaming)
- **GitHub**: raw 파일 다운 or `git clone` (garak payloads, L1B3RT4S, AdvBench).
- ⚠️ **라이선스 확인 필수** — 연구/비상업 제한 있는 것 있음. source별 license 컬럼에 기록.

### 2-4. 데이터 소스 실사 결과 (2026-07-07 직접 확인) ✅
**핵심: 크롤링 불필요 — 전부 HF `load_dataset` 또는 파일 다운로드로 접근됨. 모두 공격텍스트 컬럼 있어 스키마 fit OK.**

| 소스 | 접근 | 규모 | 공격텍스트 컬럼(→prompt_text) | 유형 라벨 | 스키마 fit | 라이선스 |
|---|---|---|---|---|---|---|
| jailbreak_prompts.csv (로컬/verazuo) | 로컬 보유 | 1,405 | `prompt` +jailbreak,platform,source,date | source | ✅ | MIT |
| latest_jailbreaks_2026.csv (로컬) | 로컬 보유 | 55 | `prompt` +model,technique | technique | ✅ | - |
| L1B3RT4S (로컬/Pliny) | 로컬 .mkd | 다수 | 마크다운 본문 | 모델별 | ✅(파서 필요) | - |
| ATLAS.yaml (로컬) | 로컬 보유 | 432기법 | (라벨 마스터, 공격 아님) | — | 라벨용 | MITRE |
| ⭐**Necent 통합본** | HF `load_dataset` | 1M~10M(411MB) | `prompt` +prompt_type,category,source,attack_technique,model_name,harmful/adversarial | 다수 | ✅✅ **최상** | MIT(코드)/소스별 상이 |
| TrustAIRLab in-the-wild | HF | 21.5k(탈옥 1.41k) | `prompt` +jailbreak,platform,source,date | jailbreak | ✅ | MIT |
| HackAPrompt | HF | 100k~1M(150MB) | `prompt`/`user_input` +correct,model | correct=성공 | ✅ | MIT |
| JBB-Behaviors | HF(`behaviors`) | 100해+100무해 | `Goal` +Category,Source | Category | ✅(목표문) | MIT |
| AdvBench | HF(로그인) | 500 | behavior/goal | — | ✅(목표문) | MIT |
| SPML injection | HF | 10k~100k | System/User prompt+label(추정) | label | ✅ | MIT |
| Lakera Gandalf | HF | 1,000 | `text` +similarity | injection | ✅ | MIT |
| HarmBench | HF(로그인)/GitHub | <1k | behavior +category | category | ✅(목표문) | MIT |
| SALAD-Bench(attack) | HF(`attack_enhanced_set`) | 5,000 | `augq` +method(gptfuzz/tap/gcg/autodan),category | method | ✅ | Apache-2.0 |
| Qualifire injections | HF(로그인) | 5,000 | `text` +label(jailbreak/benign) | label | ✅ | ⚠️**CC-BY-NC**(비상업) |
| garak payloads | GitHub clone | 코드 생성 | probe 코드(정적 payload 적음) | probe별 | △ 추출 번거로움 | Apache-2.0 |

**발견/주의:**
1. **크롤링 안 해도 됨** — 전부 API(`load_dataset`)/파일 제공. garak만 예외(probe 코드에서 동적 생성 → 추출 번거로움, 후순위).
2. **두 종류**: (a) **완성 공격 프롬프트**(바로 씨앗) = in-the-wild·Gandalf·HackAPrompt·L1B3RT4S·SALAD·SPML / (b) **목표문(짧은 harmful behavior)** = AdvBench·HarmBench·JBB → 그대로 씨앗보다 "objective"로 쓰거나 프롬프트로 감싸야.
3. **라이선스**: 대부분 MIT/Apache지만 **Qualifire = CC-BY-NC(비상업)** ⚠️. Necent는 통합코드 MIT지만 **소스별 원 라이선스 상이** → 상업화 시 소스별 감사 필요. 부트캠프/연구용은 OK.
4. **일부 HF 로그인+약관동의 필요**(AdvBench/HarmBench/Qualifire) → HF 계정/토큰 준비.
5. **가성비 순위**: ⭐Necent 통합본(30+ 한방) → in-the-wild → SALAD attack_enhanced → HackAPrompt(correct=True 필터) → 나머지.
6. **스키마 매핑(공통)**: 공격텍스트→`prompt_text`, 유형/technique/label→`attack_type`·`tags`, model→`worked_on`, 성공flag(correct/jailbreak)→`verified` 후보, source명→`source`, →`atlas_technique_id`(매핑), →`embedding`(생성).

### 2-5. ⚠️ ATLAS 13유형 커버리지 (유형별 소스 — 편향 주의)
**핵심: 확인해보니 데이터가 "탈옥+직접인젝션"에 쏠려 있음. 13유형 균등 커버가 아님 → 유형별로 전용 소스를 붙여야 함.**

| # | 공격유형(attack-type) | ATLAS | 유형별 데이터 소스 | 커버 |
|---|---|---|---|---|
| 1 | direct_prompt_injection | T0051.000 | verazuo·Gandalf·SPML·HackAPrompt·Qualifire·Necent | ✅ 풍부 |
| 2 | indirect_prompt_injection | T0051.001 | **BIPIA**(250), **InjecAgent**(1,054), **AgentDojo**(629) — 외부문서/툴 경유 | ◐ 전용 소스로 보강 |
| 3 | jailbreak | T0054 | verazuo 1,405·in-the-wild·SALAD·L1B3RT4S | ✅✅ 최다 |
| 4 | system_prompt_extraction | T0056 | Gandalf·LeakAgent(시스템프롬프트 추출) | ◐ 부분 |
| 5 | prompt_leakage | T0056 | 위와 동일 | ◐ 부분 |
| 6 | data_leakage | T0057 | AdvBench/HarmBench(목표)·**AgentLeak**·LeakAgent | ◐ 부분 |
| 7 | pii_leakage | T0057 | **PII-Scope**·**ai4privacy/pii-masking-200k**·LeakSealer | ◐ 전용 소스로 보강 |
| 8 | tool_function_abuse | T0053 | **InjecAgent**·**AgentDojo**(툴콜 공격) | ◐ 에이전트 소스 |
| 9 | tool_manipulation | T0053 | 위와 동일 | ◐ 에이전트 소스 |
| 10 | roleplay_persona | T0054 | verazuo(롤플레이 다수) | ✅ |
| 11 | encoding_obfuscation | T0051.000 | Necent(base64)·L1B3RT4S(leetspeak)·garak(encoding) | ✅ |
| 12 | hallucination_induction | T0062 | ❌ 전용 데이터셋 드묾(misinformation 별개) | ✗ **부족** |
| 13 | dos | T0029 | ❌ 전용 드묾(sponge/자원고갈·초장문) | ✗ **부족** |

**정직한 결론:**
- **강함(풍부)**: jailbreak·roleplay·direct injection·encoding (≈4유형)
- **전용 소스로 보강 가능**: indirect injection(BIPIA/InjecAgent/AgentDojo), PII/data leakage(PII-Scope/ai4privacy/AgentLeak), tool abuse(InjecAgent/AgentDojo), system prompt extraction(Gandalf/LeakAgent)
- **부족(데이터 드묾)**: **hallucination_induction·dos** → 데이터셋이 거의 없어 **규칙/템플릿으로 자체 생성**하거나 **후순위/범위제외**. (이 둘은 A2에서 ATLAS 마스터에도 없던 유형 — 재검토 대상)

**수집 전략(수정)**: "탈옥만" 말고 **유형별로 골고루** 긁는다 →
1. 탈옥/롤플레이/인젝션/인코딩 = Necent+in-the-wild+SALAD로 대량
2. **indirect·tool = InjecAgent·AgentDojo·BIPIA 추가**(에이전트 공격, 우리 tool_abuse 유형 채움)
3. **PII/data leakage = PII-Scope·ai4privacy 추가**
4. hallucination·DoS = 자체 템플릿 or 제외

**최신성(사용자 요청: old+new 섞기)**: 옛것(verazuo 2023, 기법은 여전히 유효) + 최신(latest_2026·L1B3RT4S 계속 업데이트·SALAD·AutoAdv 2025·JailBreakV 2024) **섞어서 다 가져옴.** 특정 시기만 편향 X.

### 2-6. 조사 진행 현황 + 소스 상세(날짜·모델) + 다른 유형 찾는 법 (2026-07-07)

**A. 어디까지 파악했나**
- ✅ 15개 소스 **직접 실사**(컬럼·접근·라이선스·스키마 fit) → §2-4
- ✅ **13유형 커버리지 매핑** → §2-5 (탈옥/인젝션 편향 확인, 부족유형 식별)
- ✅ **부족 유형 보강 소스 발굴**(indirect injection·tool·PII/data leakage)
- ⏳ 아직 컬럼 상세 실사 안 한 것: BIPIA·InjecAgent·AgentDojo·PII-Scope·ai4privacy(존재·용도만 확인) / hallucination·DoS 전용 소스(거의 없음 확인)
- ⚠️ **실제 적재는 안 함(확인만)** — 토큰 절약

**B. 소스별 상세 (날짜·모델·규모)**

| 소스 | 날짜(수집기간) | 대상 모델 | 규모 | 유형 |
|---|---|---|---|---|
| verazuo/jailbreak_llms (로컬) | 2022-12~2023-12 | ChatGPT(GPT-3.5/4)기 | 15,140(탈옥 1,405) | 탈옥 |
| latest_jailbreaks_2026 (로컬) | 2026 | **OPUS-4.5/4.6·GPT-5.2**(최신) | 55 | 탈옥(모델별) |
| L1B3RT4S/Pliny (로컬) | **계속 업데이트** | 최신(GPT-5.2·Opus·Gemini·DeepSeek·Meta) | 모델별 다수 | 탈옥·난독화 |
| Necent 통합본 | 혼합(집계) | 다수 | 1M~10M(411MB) | 다수(통합) |
| TrustAIRLab in-the-wild | 2022-12~2023-12 | ChatGPT | 21,527(탈옥 1.41k) | 탈옥 |
| HackAPrompt | 2023(대회) | GPT-3.5·FlanT5-XXL | 100k~1M | 인젝션 |
| JBB-Behaviors | 2024 | (행동 목표) | 100+100 | 목표문 |
| AdvBench | 2023 | (행동 목표) | 500 | 목표문 |
| SPML | - | 챗봇 | 10k~100k | 인젝션 |
| Lakera Gandalf | 2023-07 | Gandalf게임 | 1,000 | 인젝션·시스템프롬프트유출 |
| HarmBench | 2024-02 | (행동 목표) | <1k | 목표문 |
| SALAD-Bench | 2024 | 다수 | 30k(공격 5k) | 다수(gptfuzz/tap/gcg/autodan) |
| Qualifire | - | - | 5,000 | 인젝션 |
| BIPIA | 2023 | - | 250목표×시나리오 | **indirect injection** |
| InjecAgent | 2024 | 툴통합 에이전트 | 1,054(툴17+62) | **indirect·tool abuse** |
| AgentDojo | 2024 | 에이전트(메일/뱅킹/여행) | 629 보안테스트 | **indirect·tool abuse** |
| PII-Scope | 2024 | 사전학습LLM | 벤치 | **PII 추출** |
| ai4privacy/pii-masking-200k | - | - | 200k(PII 3,624+) | **PII** |

**C. 다른(부족) 유형 소스 찾는 법**
- **어디서**: HuggingFace Datasets 검색 + arXiv(논문→GitHub/HF 링크) + 큐레이션 리스트(`byoniq/AI-Redteaming`·`awesome-mllm-guardrails`·`Libr-AI/OpenRedTeaming`).
- **유형별 검색어**:
  - indirect injection/tool: `InjecAgent`, `AgentDojo`, `BIPIA`, "indirect prompt injection dataset", "tool-integrated agent attack"
  - system prompt/데이터 유출: "system prompt leakage/extraction dataset", `LeakAgent`, `AgentLeak`
  - PII: `PII-Scope`, `ai4privacy/pii-masking-200k`, "PII extraction LLM"
  - hallucination(T0062): "hallucination induction adversarial", "misinformation prompt dataset"(전용 적음→자체 템플릿)
  - DoS(T0029): "LLM denial of service sponge prompt"(전용 거의 없음→자체 생성)
- **판단 기준**: ①공격텍스트 컬럼 有 ②유형/라벨 有 ③접근(load_dataset/다운) ④라이선스(부트캠프=연구용이라 대부분 무관) ⑤날짜·모델(old+new 섞기).
### 2-7. 부족유형(indirect/tool/PII) 소스 실사 결과 (2026-07-07 이어서)

| 소스 | 접근/데이터파일 | 규모 | 추출 | fit | 라이선스/연도 |
|---|---|---|---|---|---|
| **BIPIA** (microsoft/BIPIA) | GitHub, `benchmark/{code,text}_attack_{train,test}.json` | 5태스크(Email/Web/Table QA·요약·Code QA), 25모델 평가 | ✅ json 바로 추출 | ✅ **indirect injection** | MIT / 2023 |
| **InjecAgent** (uiuc-kang-lab) | GitHub, `data/attacker_cases_{dh,ds}.jsonl` | 1,054(user툴17+공격툴62), direct-harm/data-stealing | ✅ jsonl 추출(attacker instruction) | ✅ **tool abuse + data exfil** | MIT / 2024-03 |
| **AgentDojo** (ethz-spylab) | GitHub, `src/agentdojo` (코드 정의) | workspace/banking/travel/slack 스위트 | △ 코드에서 추출(번거로움) | ◐ tool abuse | MIT / 2024(NeurIPS) |
| ai4privacy/pii-masking-200k | HF | 209k(EN/FR/DE+) | ❌ | ✗ **공격 아님** | - |

**정정/주의 (중요):**
- ⚠️ **ai4privacy = 공격 프롬프트 아님.** PII **탐지(NER) 학습 데이터**(원문+마스킹, `source_text/privacy_mask`). 우리 `attack_cases` 씨앗으론 **부적합**. → PII 유출 "공격"은 **PII-Scope·LeakAgent류(공격형)** 가 맞음(다음 실사).
- **BIPIA·InjecAgent = json/jsonl로 바로 추출 가능** → indirect injection·tool abuse 유형을 실제로 채울 수 있음 확인. AgentDojo는 코드기반이라 후순위.
- **남은 실사 대상**: PII-Scope·LeakAgent(공격형 PII 추출) / hallucination(T0062)·DoS(T0029) 전용(거의 없음).

### 2-8. 최종 결론 — 유형별 확보 방식 3가지 (조사 종료 2026-07-07)
데이터셋으로 "다 긁어오는" 유형과, 데이터가 없어 **기법/템플릿으로 만들어야** 하는 유형이 나뉨을 확인:

| 방식 | 대상 유형 | 소스/방법 |
|---|---|---|
| **① 대량 데이터 적재** (load_dataset/다운) | 탈옥·롤플레이·직접인젝션·인코딩 + **indirect·tool** | Necent·in-the-wild·SALAD·HackAPrompt·Gandalf + **BIPIA·InjecAgent**(json/jsonl 추출) → 코퍼스의 대부분 |
| **② 기법·템플릿 구현** (데이터셋 아님) | PII·data leakage·system prompt 추출(T0056/T0057) | **PII-Scope·PII-Compass·LeakAgent**의 "반복질의·grounding" *기법*을 소수 템플릿으로 → 데이터셋 아니라 방법론 |
| **③ 자체 생성** (전용 데이터 없음) | **hallucination(T0062)·DoS(T0029)** | 규칙/템플릿 자체 제작(초장문·반복·유도질문) or 범위 제외(A2에서 ATLAS 마스터에도 없던 유형) |

**→ 즉 13유형 = ①대량적재(다수) + ②템플릿구현(유출/PII) + ③자체생성(할루/DoS).** "탈옥만" 편향은 ①에 BIPIA·InjecAgent·SALAD 등을 섞고 ②③를 더해 해소.

### 2-9. 추가 발굴 소스 (2026-07-07 계속)

**대형 범용 레드팀 (양 많음, 여러 유형):**
| 소스 | 규모 | 접근 |
|---|---|---|
| ⭐ **Anthropic red-team-attempts** | **38,961** 크라우드소싱 실전 공격 대화 | HF(hh-rlhf red-team) |
| **ALERT** | ~15,000 (안전 taxonomy별) | HF |

**시스템프롬프트 추출/유출 (T0056) 보강 → ◐에서 ✅ 승격:**
| 소스 | 내용 | 접근 |
|---|---|---|
| ⭐ **Tensor Trust** | 온라인게임 실전 인젝션/추출(대량, Gandalf류 확장) | arXiv 2311.01011 |
| **Raccoon** | LLM앱 프롬프트 추출 벤치 | arXiv 2406.06737 |
| Toyer Prompt Extraction | 569 샘플 | 2023 |
| deepset/prompt-injections | ~600 인젝션 분류 | HF |
| SPE-LLM / PromptInject | 시스템프롬프트셋 / 프레임 | 논문 |

**DoS(T0029)·hallucination(T0062) = 여전히 "데이터셋 아닌 기법" 확정:**
- DoS: **Engorgio·ThinkTrap·GCG-DoS·ReasoningBomb** (EOS 억제→초장문·자원고갈) = 기법 → ③ Engorgio식 자체 템플릿.
- hallucination: 적대적 환각 유도(arXiv 2310.01469) = 기법 → ③ 자체생성/후순위.

**업데이트 결론:** T0056(시스템프롬프트 추출)은 **Tensor Trust·Raccoon으로 ✅ 승격**. 범용 대량은 **Anthropic red-team(38,961)·ALERT** 추가.

### 2-10. DoS·hallucination 2유형 — 확보 방법 확정 (조사 결과)

**hallucination_induction (T0062): 반 데이터 + 반 템플릿**
- 데이터(있음, 단 대부분 "탐지/평가"용 → 공격으로 각색): **HaluEval**(30k QA/대화/요약)·**FactCHD**(6,960 사실충돌, 7도메인)·**HypoTermQA**(가상 용어로 환각 유도).
- 방법: **AutoHall**(arXiv 2310.00259, 코드·데이터 공개) = fact-checking 데이터로 **모델별 환각셋 자동 생성** → 재활용.
- → 데이터 각색 + 템플릿(허위 전제·유도질문·가상용어)로 채움.

**dos (T0029): 전용 데이터 없음 → 자체 템플릿(기법 재현)**
- 공개 데이터셋 없음 확인. 전부 최적화 *기법*: **ThinkTrap**(무한 사고 유도)·**Engorgio**(ICLR'25, EOS 억제→babble)·**LoopLLM/LingoLoop/Sponge Examples**.
- 방법: 기법을 **소수 템플릿으로 자체 제작** — EOS 억제/무한 반복/중첩 추론 유도(예: "repeat X forever", "keep reasoning without stopping", 초장문 나열).
- → 데이터 적재가 아니라 **템플릿 몇 개** 자체 제작.

**✅ 최종: 13유형 전부 확보 경로 확정.**
- 11유형 = 데이터셋 적재(Necent·in-the-wild·SALAD·BIPIA·InjecAgent·Tensor Trust·Anthropic red-team 등)
- hallucination = HaluEval/FactCHD/AutoHall **각색**(반데이터)
- DoS = Engorgio/ThinkTrap식 **템플릿 자체제작**(소량)

**소스 조사 완료.** 다음 세션 = 실제 수집→정제→dedup→임베딩→적재.

### 2-11. 소스 품질 평가 (2026-07-07)
- **믿고 씀(질 좋음)**: in-the-wild/verazuo(CCS'24)·Tensor Trust·Anthropic red-team(38,961)·SALAD·BIPIA·InjecAgent·latest_2026·L1B3RT4S.
- **쓰되 손봐야 ◐**: HackAPrompt(라벨 약함→필터)·Necent(중복·소스별 라이선스 혼재→dedup 필수)·AdvBench/HarmBench/JBB(완성 프롬프트 아닌 **목표문**)·HaluEval/FactCHD(탐지용→각색)·Gandalf(일부 노이즈).
- **제외**: ai4privacy(공격 아님, PII 탐지 데이터).
- **공통 리스크**: ①중복 심함→**dedup 필수** ②2023 편중→최신(Tensor Trust/latest_2026/L1B3RT4S) 보강 ③품질 편차→**`verified` 재검증**(더미앱 통과분만). 라이선스=부트캠프/연구용이라 무관.
- **결론**: **소스 자체는 OK(정당·실제). 정제(필터+dedup+verified)가 최종 질을 좌우.** 날것 그대로는 노이즈·중복 있음.

---

## 3. 통일 스키마 + 적재 파이프라인

### 3-1. 목표 스키마 = `attack_cases`
`prompt_text, attack_type, atlas_technique_id, source, worked_on[], verified, tags[], embedding(vector 384)`

### 3-2. 파이프라인 (기획 §8)
```
1. 로드        각 소스 어댑터(source→표준레코드) — 컬럼명/구조 통일
2. 정제·필터   빈값/과장·과단·비프롬프트 제거, 언어 태그, 최대길이 컷
3. 분류        attack_type 라벨(규칙/키워드 or 소스 메타) — jailbreak/prompt_injection/data_leakage/pii/…
4. ATLAS 매핑  attack_type → atlas_technique_id 정적 테이블
5. dedup       임베딩 유사도로 중복 클러스터링(대량→대표) — exact + near-dup(코사인 임계)
6. 임베딩      sentence-transformers all-MiniLM-L6-v2(384d, 무료 로컬) 배치
7. 적재        INSERT attack_cases(...embedding) + HNSW 인덱스(cosine)
8. verified    (후속) 자체 더미앱에 돌려 통과분만 verified=true
```

### 3-3. 구현
- 파이썬 스크립트(`기획/poc/` 재활용·확장): 소스별 어댑터 + 공통 정제/임베딩/적재.
- `psycopg` + pgvector, 배치 INSERT(수천 단위 commit).
- 임베딩 모델 384d(MiniLM) → 저장 = N × 384 × 4B. 예: 5만개 ≈ 77MB(벡터) + 텍스트. **로컬·RDS 20GB 다 여유**(Neon 0.5GB는 규모 봐서).
- 중복 제거로 "60만 → 대표 수천~수만" 압축(기획 §5.2) → 실제 적재량·비용 절감.

---

## 4. 착수 순서 (다음 세션)
1. 로컬 `docker compose up`(pgvector) 확인 → `attack_cases`에 `embedding vector(384)` 컬럼·HNSW 준비(모델 리팩터와 함께).
2. 수집 스크립트: 먼저 **Necent 통합본 + TrustAIRLab in-the-wild** 부터(가성비 최고) → 점차 추가.
3. 통일·정제·dedup·임베딩·적재 파이프라인 1개 소스로 관통 → 나머지 소스 확장.
4. 규모·품질 보고 → 배포 DB(RDS free / Neon) 결정·이관.

---

## 5. 운영 — 영속성 · 이관 · 팀 공유

### 5-1. 로컬 Docker 영속성 (컴퓨터 꺼도 안 사라짐)
- `docker-compose.yml`에 **named volume 이미 있음**: `pgdata:/var/lib/postgresql/data`. 데이터는 컨테이너가 아니라 **볼륨(디스크)** 에 저장 → 컨테이너 껍데기가 사라져도 데이터는 남음.
- **컴퓨터 재부팅 · `compose stop` · `compose down` 다 데이터 유지** → `docker compose up`이면 복구.
- ⚠️ **`docker compose down -v` (또는 `docker volume rm pgdata`)만 데이터 삭제** — `-v` 플래그 금지.
- 안전장치: 적재 후 **`pg_dump` 백업 파일 1개** 떠두기(볼륨 날아가도 몇 분이면 재적재, 배포 이관에도 재사용 = 일석이조).

### 5-2. 로컬 → RDS 이관 (덤프 부어넣기)
```bash
pg_dump -h localhost -U redteam redteam > redteam_corpus.sql          # 로컬 완성본 덤프
# RDS 띄운 뒤:
psql -h <rds> -U redteam -d redteam -c "CREATE EXTENSION IF NOT EXISTS vector;"
psql -h <rds> -U redteam -d redteam < redteam_corpus.sql             # 부어넣기
```
- **무거운 작업(수집·정제·임베딩)은 로컬 1회, RDS는 결과만 받음 = 비용 최소.**
- 앱은 `DATABASE_URL`만 RDS로 교체. HNSW 인덱스는 덤프 포함 or 한 줄 재생성.

### 5-3. 팀 공유 (RDS 안 쓰고)
로컬 pgvector "실행 중인 것"은 그 사람 PC에만 있음 → 그대로는 공유 불가. 대신:
| 방법 | 방식 | 오프라인 | 비용 | 단일소스 | 추천 |
|---|---|---|---|---|---|
| **① 덤프/스크립트 공유** | 한 명 적재→`pg_dump`→공유(Git LFS/드라이브), 각자 restore | ✅ | 무료 | ❌(복사본) | ⭐ 씨앗=읽기위주라 최적 |
| **② 무료 Neon 공유 DB** | Neon 1개 띄워 팀 전부 접속 | ❌ | ~무료(scale-to-zero) | ✅ | ⭐ "다 같이 하나" 원하면 |
| ③ 로컬 네트워크 노출 | ngrok/tailscale로 포트 오픈 | ❌ | 무료 | ✅ | 비추(불안정) |
- **코퍼스는 잘 안 바뀌는 참조 데이터**라 ①(각자 로컬 복사본)이 개발엔 제일 편함(공유 서버·인터넷 의존 없음).
- 소스 CSV + 적재 스크립트가 repo에 있어 **팀원이 스크립트만 돌려도 재생성** 가능. (임베딩 시간 아끼려면 완성 덤프 공유)

> 관련: `아키텍처-기술스택.md §3.2`(pgvector 근거), `기획.md §5.2·§8`(검색·데이터), `ERD-완전정리.md`(attack_cases), `NEXT.md`(로드맵)
>
> 출처: AWS RDS PostgreSQL Pricing/Free Tier, Supabase·Neon 무료티어 문서, HuggingFace(Necent 통합 데이터셋·TrustAIRLab·HackAPrompt), JailbreakBench(NeurIPS'24), NVIDIA garak, 큐레이션 리스트(byoniq/AI-Redteaming 등).
