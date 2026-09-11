# ---------------------------------------------------------------------------
# Stage 1 — build
# Dependencies are compiled here (lxml and trafilatura have C extensions),
# and only the result is copied into the final image.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

# Self-contained virtual environment, copied as-is into the next stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# ---------------------------------------------------------------------------
# Stage 2 — runtime
# No compiler, no dev headers: smaller attack surface, lighter image.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 \
        libxslt1.1 \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user: the bot has no reason to run as root.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 cyberwatch

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --chown=cyberwatch:cyberwatch *.py feeds.yaml ./

USER cyberwatch

# Checks that the process is alive and the config loads.
HEALTHCHECK --interval=5m --timeout=15s --start-period=45s --retries=3 \
    CMD python -c "import config; import sys; sys.exit(0 if config.settings.feeds else 1)"

CMD ["python", "-u", "bot.py"]