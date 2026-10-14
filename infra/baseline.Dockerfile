FROM python:3.13.16-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --group baseline --no-cache
COPY lab_baseline ./lab_baseline
COPY fixtures/company.json ./fixtures/company.json
COPY scripts/phase5_evaluation.py ./scripts/phase5_evaluation.py
COPY config/phase5-model-cases.json ./config/phase5-model-cases.json
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
CMD ["python", "-m", "lab_baseline.supervisor"]
