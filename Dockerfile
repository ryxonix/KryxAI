# syntax=docker/dockerfile:1
#
# KryxAI API image — Render free tier, Cloud Run, or any Docker host.
#
# Single stage on purpose: the React SPA is built and served by a separate
# static site (see render.yaml), so this image needs no Node toolchain and no
# multi-stage build.
#
# Installs the [api,reports] extras but deliberately NOT [model]: onnxruntime
# costs roughly 200 MB of resident memory and the free tier has 512 MB in
# total. No risk_model.onnx ships in the repository, so nothing is lost — the
# rules score alone and the report records that no model contributed.

FROM python:3.12-slim

# PYTHONUNBUFFERED keeps uvicorn output streaming to Render's log drain instead
# of sitting in a stdio buffer where a crash would hide the reason.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    KRYXAI_HOME=/data \
    PORT=10000

WORKDIR /app

# README.md and LICENSE are not optional extras: pyproject.toml declares
# `readme = "README.md"` and `license-files = ["LICENSE"]`, and the build fails
# without them. They are copied alongside pyproject.toml so that editing the
# package source does not invalidate the dependency layer.
COPY pyproject.toml README.md LICENSE ./
COPY kryxai ./kryxai
RUN pip install ".[api,reports]"

# The evidence database, rendered reports, and the generated report signing key
# all live under KRYXAI_HOME. Render's free tier has no persistent disk, so
# this is wiped on every spin-down and redeploy.
RUN mkdir -p /data && chmod 700 /data

# Render already probes /health via healthCheckPath in render.yaml; this
# HEALTHCHECK is for local `docker run` and for Cloud Run. It reads PORT at
# runtime rather than baking in a literal, because the host assigns the port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','10000')+'/health', timeout=4)"]

EXPOSE 10000

# `sh -c` rather than bare shell form: $PORT is injected by the host at runtime
# and must be expanded by a shell, but `exec` then replaces that shell with
# uvicorn so uvicorn is PID 1 and receives SIGTERM directly. Without the exec,
# Render's graceful-shutdown signal would hit the shell and uvicorn would be
# killed by the timeout instead of draining.
#
# One worker on purpose: rendered report bodies are held in a per-process LRU
# (see _SCAN_CACHE_MAX in kryxai/api.py), so a second worker would answer 404
# for a scan that the first worker had analysed.
CMD ["sh", "-c", "exec uvicorn kryxai.api:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1"]
