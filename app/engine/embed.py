# -*- coding: utf-8 -*-
"""질의 임베딩(런타임) — 씨앗 벡터검색용. — #130 (기획 §5.2)

코퍼스 임베딩(load_corpus의 attack_cases.embedding)이 all-MiniLM-L6-v2(384d)로
만들어졌으므로, 질의도 '같은 모델'로 임베딩해야 코사인이 의미 있다.

원칙(배포 안전):
- 모델은 프로세스당 1회만 로드(지연 로드 + 캐시). RETRIEVE_VECTOR_ENABLED=on일 때만 로드됨.
- 로드/임베딩 실패(미설치·RAM·다운로드 불가) → None 반환 → retrieve가 메타필터로 폴백.
  fastembed(onnxruntime)는 torch 없이 가벼운 편이나 t3.micro(1GB) RAM은 검증 후 켤 것.
"""
import logging
import threading

log = logging.getLogger("redteam.embed")

_model = None
_load_tried = False
_lock = threading.Lock()


def _get_model():
    """fastembed TextEmbedding을 1회 로드(캐시). 실패 시 None(재시도 안 함)."""
    global _model, _load_tried
    if _model is not None or _load_tried:
        return _model
    with _lock:
        if _model is not None or _load_tried:
            return _model
        _load_tried = True
        try:
            from fastembed import TextEmbedding

            from ..config import settings
            _model = TextEmbedding(model_name=settings.embed_model)
            log.info("embed: 질의 임베딩 모델 로드 완료 — %s", settings.embed_model)
        except Exception as e:  # noqa: BLE001 - 미설치/RAM/다운로드 실패 → 폴백
            log.warning("embed: 모델 로드 실패 → 메타필터 폴백: %s", e)
            _model = None
        return _model


def embed_query(text):
    """질의 텍스트 → 384d float 리스트. 빈입력/실패면 None(→ 메타필터 폴백)."""
    if not text or not str(text).strip():
        return None
    model = _get_model()
    if model is None:
        return None
    try:
        vecs = list(model.embed([str(text)]))
        if not vecs:
            return None
        return [float(x) for x in vecs[0]]
    except Exception as e:  # noqa: BLE001 - 런타임 임베딩 실패 → 폴백
        log.warning("embed: 질의 임베딩 실패: %s", e)
        return None
