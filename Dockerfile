# Wedgecheck: FastAPI app on top of gpt-researcher (Apache-2.0).
#
# No torch/sentence-transformers here on purpose -- production points
# EMBEDDING at "custom:bge" (this portfolio's free Cloudflare Workers AI
# relay's /v1/embeddings route) instead of local HuggingFace embeddings, so
# the image stays small and fast to build on the arm64 Oracle box.
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY web ./web
COPY cli.py ./cli.py

# Writable at runtime for cli.py's ./output/ (the web app itself doesn't
# need it, but keep the dir present and writable either way) and for
# app/store.py's SQLite DB (./data/wedgecheck.db by default -- WEDGECHECK_DB_PATH
# to relocate it). Mount a volume at /app/data in production or saved
# briefs/permalinks won't survive a container recreate.
RUN mkdir -p /app/output /app/data && useradd -u 10001 -m wedgecheck \
    && chown -R wedgecheck:wedgecheck /app
USER wedgecheck

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
