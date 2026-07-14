# -*- coding: utf-8 -*-
"""완화(mitigation) 정본 라이브러리 — 기법별 구조화 실행 가이드. — 이슈 #79

finding 카드·atlas 참조가 쓰는 완화책의 단일 정본. 결정론적 큐레이션(LLM 미사용, 정확성 우선).
스코프 = 엔진이 실제 objective로 생성하는 ATLAS id(recon._TYPE_TO_ATLAS의 고유값)
+ base(AML.T0051) 폴백 + 미매핑 일반 폴백.

구조화 완화 1건 스키마:
    {
      "summary":    str,          # 한 줄 핵심(= DB findings.mitigation 스냅샷으로도 사용)
      "cause":      str,          # 왜 뚫렸는가
      "steps":      list[str],    # 실행 가능한 조치(우선순위 순)
      "verify":     str,          # 조치 후 검증법
      "references": list[dict],   # [{"label", "url"}] 공식 근거
    }

주의: 완화 문구는 보안 정확성 리뷰(팀/멘토) 대상.
외부 링크는 텍스트 상수(런타임 호출 없음) → 예외처리 불필요.
"""
from copy import deepcopy

# 자주 쓰는 공식 근거 링크(상수).
_OWASP_LLM01 = {"label": "OWASP LLM01 Prompt Injection",
                "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"}
_OWASP_LLM02 = {"label": "OWASP LLM02 Sensitive Information Disclosure",
                "url": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/"}
_OWASP_LLM06 = {"label": "OWASP LLM06 Excessive Agency",
                "url": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/"}


def _atlas_ref(technique_id: str) -> dict:
    """MITRE ATLAS 기법 상세 링크 참조 dict."""
    return {"label": f"MITRE ATLAS {technique_id}",
            "url": f"https://atlas.mitre.org/techniques/{technique_id}"}


# 미매핑 기법에 안전하게 반환하는 일반 가이드.
_FALLBACK = {
    "summary": "입력 검증·시스템프롬프트 격리·출력 필터로 민감정보 유출을 차단하세요",
    "cause": "신뢰할 수 없는 입력이 모델 동작에 영향을 주고 출력 검증이 없음",
    "steps": [
        "시스템 지침·비밀을 사용자 입력과 분리·구획화",
        "입력 정규화·지시성 문구 탐지로 조작 시도 차단",
        "출력에 비밀·PII·시스템프롬프트 스캔 후 마스킹·차단",
        "입출력 가드레일과 최소권한·레이트리밋 적용",
    ],
    "verify": "동일 공격 프롬프트를 재발사(스캔 재실행)해 차단/거부되는지 확인",
    "references": [
        {"label": "OWASP Top 10 for LLM Applications", "url": "https://genai.owasp.org/"},
        {"label": "MITRE ATLAS", "url": "https://atlas.mitre.org/"},
    ],
}

# ── 기법별 구조화 완화 정본 (키 = 정규 ATLAS id) ──
_MITIGATIONS: dict[str, dict] = {
    # 탈옥
    "AML.T0054": {
        "summary": "안전 가드레일이 우회돼 금지된 동작(비밀 노출·역할 이탈·정책 위반)이 수행됨",
        "cause": "역할극·가상 시나리오·단계적 설득으로 안전 지침보다 사용자 지시가 우선 적용됨",
        "steps": [
            "비밀·키·내부지침을 시스템프롬프트에서 분리(서버 로직/별도 저장소로)",
            "탈옥 유도 패턴(DAN·roleplay·'제한 없는'·가상 시나리오) 입력 탐지·차단",
            "시스템 지침을 응답마다 재확인하는 우선순위 고정(입력이 지침을 못 덮게)",
            "출력에 카나리·시스템프롬프트·정책위반 스캔 후 차단·마스킹",
            "입출력 가드레일(llm-guard 등) 적용",
        ],
        "verify": "동일 탈옥 프롬프트를 재발사(스캔 재실행)해 차단/거부되는지 확인",
        "references": [_OWASP_LLM01, _atlas_ref("AML.T0054")],
    },
    # 프롬프트 인젝션(일반 base)
    "AML.T0051": {
        "summary": "신뢰할 수 없는 입력이 모델 지침을 조작해 의도치 않은 동작이 발생함",
        "cause": "지침과 데이터가 한 컨텍스트에 섞여 입력에 심긴 지시가 실행됨",
        "steps": [
            "시스템 지침과 사용자/외부 데이터를 컨텍스트에서 명확히 구획화",
            "지시성 문구(ignore/override/system·역할 전환) 탐지·차단",
            "입력 정규화(인코딩·다국어 디코딩) 후 재검사",
            "출력 스캔으로 비밀·PII·시스템프롬프트 유출 차단",
        ],
        "verify": "대표 인젝션 프롬프트를 재발사해 차단/거부되는지 확인",
        "references": [_OWASP_LLM01, _atlas_ref("AML.T0051")],
    },
    # 직접 프롬프트 인젝션
    "AML.T0051.000": {
        "summary": "사용자 입력이 시스템 지침을 덮어써 비밀·지침이 노출됨",
        "cause": "입력과 시스템 지침이 같은 컨텍스트에 섞여 '이전 지침 무시' 류가 우선 적용됨",
        "steps": [
            "비밀·키·내부지침을 시스템프롬프트에서 분리(서버 로직/별도 저장소로)",
            "입력을 '데이터'로 구획화 + 지시성 문구(ignore/override/system) 탐지·차단",
            "입력 정규화: base64·leetspeak·homoglyph·다국어 디코딩 후 재검사",
            "출력에 카나리/시스템프롬프트/PII 스캔 후 마스킹·차단",
            "입출력 가드레일(llm-guard 등) 적용",
        ],
        "verify": "동일 인젝션을 재발사(스캔 재실행)해 차단/거부되는지 확인",
        "references": [_OWASP_LLM01, _atlas_ref("AML.T0051")],
    },
    # 간접 프롬프트 인젝션(RAG·외부 콘텐츠)
    "AML.T0051.001": {
        "summary": "외부 콘텐츠(문서·웹·툴 결과)에 숨은 지시가 모델에 간접 실행됨",
        "cause": "RAG·툴로 가져온 외부 데이터를 모델이 신뢰된 지시로 취급함",
        "steps": [
            "외부·검색·툴 결과를 '지시'가 아닌 '데이터'로만 취급(구획 태깅)",
            "RAG/툴 입력 살균(sanitize): 숨은 지시·마크업·주석 제거",
            "출처 신뢰도 등급화, 미검증 출처의 지시성 콘텐츠 차단",
            "부작용 있는 툴 호출은 사용자 확인·safe_mode 게이트 뒤에 배치",
            "출력 스캔으로 유출·비정상 행동 차단",
        ],
        "verify": "악성 지시를 심은 외부 문서로 재발사해 지시가 무시되는지 확인",
        "references": [_OWASP_LLM01, _atlas_ref("AML.T0051.001")],
    },
    # 시스템 프롬프트 유출
    "AML.T0056": {
        "summary": "모델이 숨겨진 시스템프롬프트(설정·규칙)를 그대로 노출함",
        "cause": "메타 질문·복사 요청에 시스템프롬프트가 응답 컨텍스트로 노출됨",
        "steps": [
            "시스템프롬프트에 비밀·키·자격증명 저장 금지(민감값은 서버 측에)",
            "시스템 메시지 복사·요약·번역 요청 거부 규칙",
            "메타 질문('너의 지침/설정이 뭐야') 탐지·차단",
            "출력에 시스템프롬프트 지문(고유 문구·카나리) 스캔 후 차단",
        ],
        "verify": "시스템프롬프트 추출 프롬프트를 재발사해 노출이 없는지 확인",
        "references": [_OWASP_LLM02, _atlas_ref("AML.T0056")],
    },
    # 도구/플러그인 오용(과잉 권한)
    "AML.T0053": {
        "summary": "연결된 툴·함수·플러그인이 의도 밖으로 호출돼 권한이 오용됨",
        "cause": "툴 호출 권한이 과도하고 파라미터 검증·확인 게이트가 없음",
        "steps": [
            "툴 권한 최소화(least privilege): 필요한 액션만 화이트리스트",
            "파라미터 화이트리스트·범위 검증(금액·대상·경로 제한)",
            "부작용 있는 액션은 safe_mode/드라이런·사용자 확인 뒤 실행",
            "툴 호출 로깅·레이트리밋으로 오남용 탐지",
        ],
        "verify": "위험 액션 유도 프롬프트를 재발사해 확인 게이트에서 막히는지 확인",
        "references": [_OWASP_LLM06, _atlas_ref("AML.T0053")],
    },
    # 데이터 유출(PII·민감정보)
    "AML.T0057": {
        "summary": "컨텍스트·학습 데이터의 민감정보(PII·비밀)가 유도되어 유출됨",
        "cause": "민감 데이터가 컨텍스트에 노출되고 출력 필터(DLP)가 없음",
        "steps": [
            "컨텍스트 주입 전 PII·비밀 마스킹/토큰화",
            "출력 DLP 스캔(이메일·카드·주민번호 패턴) 후 마스킹·차단",
            "이전 대화·타 사용자 데이터 접근 격리(세션·테넌트 분리)",
            "최소수집·보존기간 정책으로 노출면 축소",
        ],
        "verify": "PII 재요청 프롬프트를 재발사해 마스킹/거부되는지 확인",
        "references": [_OWASP_LLM02, _atlas_ref("AML.T0057")],
    },
}


def get_mitigation(atlas_id: str | None) -> dict:
    """ATLAS 기법 id → 구조화 완화 dict(딥카피). 미매핑은 base 폴백 → 일반 폴백.

    - atlas_id: 'AML.T0051.000' 같은 정규 id. None·미지 값도 안전(일반 폴백 반환).
    - 딥카피 반환 → 호출측이 정본 dict를 변형하지 못하게 격리.
    """
    if not atlas_id:
        return deepcopy(_FALLBACK)
    key = str(atlas_id).strip()
    if key in _MITIGATIONS:
        return deepcopy(_MITIGATIONS[key])
    # 'AML.T0051.000' → base 'AML.T0051' 폴백
    if "." in key:
        base = key.rsplit(".", 1)[0]
        if base in _MITIGATIONS:
            return deepcopy(_MITIGATIONS[base])
    return deepcopy(_FALLBACK)
