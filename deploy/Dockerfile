# mcpnuke-runner: HTTP job API around the mcpnuke scanner.
# Build from the repo root:
#   docker build -t mcpnuke/runner:latest -f deploy/Dockerfile .
FROM python:3.13-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY mcpnuke ./mcpnuke
RUN pip install --no-cache-dir --prefix=/install ".[server]"

FROM python:3.13-slim
RUN groupadd -r mcpnuke && useradd -r -g mcpnuke -d /app mcpnuke
COPY --from=builder /install /usr/local
WORKDIR /app
USER mcpnuke

ENV MCPNUKE_RUNNER_HOST=0.0.0.0 \
    MCPNUKE_RUNNER_PORT=8090 \
    MCPNUKE_RUNNER_WORKERS=2

EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/health')"

CMD ["mcpnuke-runner"]
