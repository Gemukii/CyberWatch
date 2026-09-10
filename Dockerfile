# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Étage 1 — build
# Les dépendances sont compilées ici (lxml et trafilatura ont des extensions C)
# puis seul le résultat est copié dans l'image finale.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# Outils de compilation nécessaires à lxml, absents de l'image slim.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

# Environnement virtuel autonome, copié tel quel à l'étage suivant.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# ---------------------------------------------------------------------------
# Étage 2 — runtime
# Ni compilateur ni en-têtes de dev : surface d'attaque réduite, image plus
# légère.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

# Bibliothèques partagées requises à l'exécution par lxml.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 \
        libxslt1.1 \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur non privilégié : le bot n'a aucune raison de tourner en root.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 cyberwatch

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --chown=cyberwatch:cyberwatch *.py feeds.yaml ./

USER cyberwatch

# Vérifie que le processus est vivant et que la config se charge.
# Le bot ne sert aucun port, donc pas de sonde HTTP possible.
HEALTHCHECK --interval=5m --timeout=15s --start-period=45s --retries=3 \
    CMD python -c "import config; import sys; sys.exit(0 if config.settings.feeds else 1)"

CMD ["python", "-u", "bot.py"]
