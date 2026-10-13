FROM python:3.13.16-slim
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-cache
USER 65532:65532
CMD ["/app/.venv/bin/uvicorn", "service_desk.sink:create_sink", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
