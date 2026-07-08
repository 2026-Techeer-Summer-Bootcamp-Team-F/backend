# AI 레드팀 백엔드 — ARCHITECTURE.md §8 (FastAPI + Celery base)
# 도커 자체 python 3.11 → 로컬 homebrew pip 깨짐과 무관(깨끗).
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# (옵션) BrowserActor용 Playwright — 주석 해제 시 이미지 ~500MB↑
# RUN pip install --no-cache-dir playwright && playwright install --with-deps chromium

COPY . .

EXPOSE 8000
# PoC: uvicorn 단독. 운영: gunicorn -k uvicorn.workers.UvicornWorker -w 4
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
