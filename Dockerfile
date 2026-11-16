# MarlonTheBug panel — self-contained image with PDF support through WeasyPrint.
# The panel never mounts the Docker socket: tool execution is delegated to the
# tools-runner service over the internal Compose network.
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH" \
    MTB_DATA_DIR=/data

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        fonts-dejavu-core \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY marlonthebug ./marlonthebug
RUN uv sync --no-dev --extra pdf --no-install-package playwright

RUN useradd --create-home --uid 10001 mtb \
    && mkdir -p /data \
    && chown -R mtb:mtb /app /data
USER mtb

VOLUME ["/data"]
EXPOSE 8765
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=8s --start-period=25s --retries=5 \
    CMD python -c "import os,sys,urllib.request; p=os.environ.get('MTB_PANEL_PORT','8765'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+p+'/healthz', timeout=5).status == 200 else 1)"

ENTRYPOINT ["marlonthebug", "panel", "--host", "0.0.0.0", "--no-browser", "--data-dir", "/data"]
