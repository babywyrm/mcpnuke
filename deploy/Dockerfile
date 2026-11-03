# mcpnuke-runner: HTTP job API around the mcpnuke scanner.
# Build from the repo root:
#   docker build -t mcpnuke/runner:latest -f deploy/Dockerfile .
FROM python:3.13-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY mcpnuke ./mcpnuke
RUN pip install --no-cache-dir --prefix=/install ".[server]"

FROM python:3.13-slim
# Numeric UID so Kubernetes runAsNonRoot can verify the user without a lookup.
RUN groupadd -r -g 1001 mcpnuke && useradd -r -u 1001 -g mcpnuke -d /app mcpnuke
COPY --from=builder /install /usr/local
WORKDIR /app
USER 1001

# Listening on 0.0.0.0, the runner will not start without MCPNUKE_RUNNER_TOKEN
# (pass it at run time, e.g. from a Secret) or MCPNUKE_RUNNER_ALLOW_OPEN=1.
ENV MCPNUKE_RUNNER_HOST=0.0.0.0 \
    MCPNUKE_RUNNER_PORT=8090 \
    MCPNUKE_RUNNER_WORKERS=2

EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=5 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/health')"

CMD ["mcpnuke-runner"]
