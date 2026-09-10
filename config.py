"""
Configuration : variables d'environnement (.env) et sources RSS (feeds.yaml).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# override=False : les variables déjà présentes dans l'environnement
# (ex. injectées par systemd) l'emportent sur le .env.
load_dotenv(BASE_DIR / ".env", override=False)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on", "oui"}


@dataclass
class Settings:
    # --- Discord ---
    discord_token: str = os.getenv("DISCORD_TOKEN", "")
    channel_id: int = _env_int("DISCORD_CHANNEL_ID", 0)
    # Si renseigné, les commandes slash sont synchronisées instantanément sur
    # ce serveur. Sinon la synchro est globale et peut prendre jusqu'à 1 h.
    guild_id: int = _env_int("DISCORD_GUILD_ID", 0)

    # --- Planification ---
    # Fréquence de COLLECTE (gratuite). La publication, elle, est arbitrée
    # une fois par jour : voir le budget quotidien ci-dessous.
    interval_minutes: int = _env_int("INTERVAL_MINUTES", 60)
    max_age_hours: int = _env_int("MAX_AGE_HOURS", 24)
    # Durée de vie d'un candidat dans la file d'attente.
    candidate_ttl_hours: int = _env_int("CANDIDATE_TTL_HOURS", 36)
    # Nombre d'articles poussés jusqu'à l'extraction de texte + enrichissement
    # à chaque collecte. Étape gratuite en tokens, mais coûteuse en réseau.
    shortlist_limit: int = _env_int("SHORTLIST_LIMIT", 15)

    # --- Budget quotidien de publication ---
    # Sélection relative : les N meilleurs du jour, pas un seuil fixe.
    daily_quota: int = _env_int("DAILY_QUOTA", 4)
    # Nombre minimal d'articles publiés, même une journée calme. Met à 0 pour
    # autoriser les journées totalement silencieuses.
    digest_min_articles: int = _env_int("DIGEST_MIN_ARTICLES", 2)
    # Heure locale d'envoi du digest (0-23).
    digest_hour: int = _env_int("DIGEST_HOUR", 8)
    timezone_name: str = os.getenv("TIMEZONE", "Europe/Paris")
    # Plancher de pertinence, pas barre d'excellence. Pour être plus
    # sélectif, baisser DAILY_QUOTA plutôt que monter ce chiffre.
    digest_floor_score: int = _env_int("DIGEST_FLOOR_SCORE", 7)

    # --- Boucle de feedback (votes 👍 / 👎) ---
    # Le bot apprend de tes réactions. Les poids sont recalculés depuis
    # l'historique Discord, jamais stockés sur disque.
    enable_feedback: bool = _env_bool("ENABLE_FEEDBACK", True)
    # Fenêtre glissante : au-delà, les votes ne comptent plus. Tes centres
    # d'intérêt d'il y a six mois ne doivent pas figer la veille d'aujourd'hui.
    feedback_lookback_days: int = _env_int("FEEDBACK_LOOKBACK_DAYS", 30)
    # Nombre de votes requis sur un signal avant tout ajustement.
    feedback_min_votes: int = _env_int("FEEDBACK_MIN_VOTES", 3)
    # Ajustement maximal par signal. Volontairement modeste : le feedback
    # module le classement, il ne le pilote pas.
    feedback_max_adjustment: int = _env_int("FEEDBACK_MAX_ADJUSTMENT", 4)
    # Fréquence de relecture de l'historique (coûteux en appels API).
    feedback_ttl_hours: int = _env_int("FEEDBACK_TTL_HOURS", 6)
    feedback_message_limit: int = _env_int("FEEDBACK_MESSAGE_LIMIT", 500)

    # --- Urgences (publiées immédiatement, hors quota) ---
    enable_urgent: bool = _env_bool("ENABLE_URGENT", True)
    # Score EPSS au-delà duquel un article devient urgent (0-1).
    urgent_epss_threshold: float = _env_float("URGENT_EPSS_THRESHOLD", 0.7)
    # Filet de sécurité pour les sujets sans CVE (compromission majeure...).
    urgent_score_threshold: int = _env_int("URGENT_SCORE_THRESHOLD", 30)
    # Garde-fou anti-inondation : même une journée catastrophique reste bornée.
    urgent_daily_max: int = _env_int("URGENT_DAILY_MAX", 2)
    # Mention envoyée avec une alerte urgente : "none", "here", ou un ID de rôle.
    urgent_mention: str = os.getenv("URGENT_MENTION", "none").strip()

    # --- Filtrage ---
    min_score: int = _env_int("MIN_SCORE", 5)
    dedup_similarity: float = _env_float("DEDUP_SIMILARITY", 0.72)

    # --- Enrichissement (sources publiques gratuites, sans clé) ---
    # CISA KEV : catalogue officiel des vulnérabilités exploitées.
    enable_kev: bool = _env_bool("ENABLE_KEV", True)
    kev_url: str = os.getenv(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    # EPSS : probabilité d'exploitation à 30 jours (FIRST.org).
    enable_epss: bool = _env_bool("ENABLE_EPSS", True)
    epss_url: str = os.getenv("EPSS_URL", "https://api.first.org/data/v1/epss")
    enrichment_ttl_hours: int = _env_int("ENRICHMENT_TTL_HOURS", 12)

    # --- Résumé IA ---
    ai_provider: str = os.getenv("AI_PROVIDER", "gemini").strip().lower()
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    # L'offre gratuite Gemini ne couvre plus que Flash / Flash-Lite.
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:3b-instruct")
    ai_delay_seconds: float = _env_float("AI_DELAY_SECONDS", 7)
    # Backoff : nombre de tentatives et attente initiale sur erreur 429.
    ai_max_retries: int = _env_int("AI_MAX_RETRIES", 2)
    ai_backoff_seconds: float = _env_float("AI_BACKOFF_SECONDS", 30)
    # Si le quota est épuisé : True = publier un résumé heuristique dégradé,
    # False (défaut) = reporter l'article au prochain cycle.
    degrade_on_quota: bool = _env_bool("DEGRADE_ON_QUOTA", False)

    # --- Récupération du texte ---
    fetch_fulltext: bool = _env_bool("FETCH_FULLTEXT", True)
    fulltext_max_chars: int = _env_int("FULLTEXT_MAX_CHARS", 4000)
    http_timeout: int = _env_int("HTTP_TIMEOUT", 20)
    user_agent: str = os.getenv(
        "USER_AGENT", "CyberWatchBot/2.0 (+veille cyber personnelle)"
    )

    # --- État (aucune écriture disque) ---
    # Fenêtre anti-doublons, en jours. L'index est reconstruit au démarrage
    # en relisant l'historique du salon Discord.
    retention_days: int = _env_int("RETENTION_DAYS", 7)
    # Plafond de sécurité sur le nombre de messages relus. 0 = pas de plafond,
    # seule la fenêtre RETENTION_DAYS borne la lecture (recommandé).
    history_limit: int = _env_int("HISTORY_LIMIT", 0)
    # Alerte si un flux ne remonte rien pendant N cycles consécutifs.
    feed_failure_threshold: int = _env_int("FEED_FAILURE_THRESHOLD", 3)

    feeds_path: Path = BASE_DIR / os.getenv("FEEDS_FILE", "feeds.yaml")
    feeds: list[dict] = field(default_factory=list)

    def validate(self) -> list[str]:
        """Retourne la liste des problèmes bloquants (vide si tout va bien)."""
        problems = []
        if not self.discord_token:
            problems.append("DISCORD_TOKEN est vide.")
        if not self.channel_id:
            problems.append("DISCORD_CHANNEL_ID est vide ou invalide.")
        if self.ai_provider not in {"gemini", "ollama", "none"}:
            problems.append(f"AI_PROVIDER inconnu : {self.ai_provider!r}")
        if self.ai_provider == "gemini" and not self.gemini_api_key:
            problems.append(
                "AI_PROVIDER=gemini mais GEMINI_API_KEY est vide "
                "(utilise AI_PROVIDER=none pour tester sans IA)."
            )
        if not self.feeds:
            problems.append("Aucun flux RSS actif dans feeds.yaml.")
        if not 0 < self.dedup_similarity <= 1:
            problems.append("DEDUP_SIMILARITY doit être dans ]0, 1].")
        if not 0 <= self.digest_hour <= 23:
            problems.append("DIGEST_HOUR doit être entre 0 et 23.")
        if self.daily_quota < 1:
            problems.append("DAILY_QUOTA doit valoir au moins 1.")
        if not 0 < self.urgent_epss_threshold <= 1:
            problems.append("URGENT_EPSS_THRESHOLD doit être dans ]0, 1].")
        return problems

    def warnings(self) -> list[str]:
        """Problèmes non bloquants, signalés au démarrage."""
        warns = []
        # Volume quotidien maximal : digest (quota + en-tête) + urgences.
        est_messages = (
            self.daily_quota + 1 + self.urgent_daily_max
        ) * self.retention_days
        if 0 < self.history_limit < est_messages:
            warns.append(
                f"HISTORY_LIMIT={self.history_limit} est inférieur au volume estimé "
                f"({est_messages:.0f} messages sur {self.retention_days} j) : "
                "l'index anti-doublons pourrait être incomplet. Utilise 0 (illimité)."
            )
        if self.feedback_max_adjustment > self.min_score:
            warns.append(
                f"FEEDBACK_MAX_ADJUSTMENT ({self.feedback_max_adjustment}) est élevé "
                f"par rapport à MIN_SCORE ({self.min_score}) : le feedback pourrait "
                "dominer le scoring factuel."
            )
        if self.digest_min_articles > self.daily_quota:
            warns.append(
                f"DIGEST_MIN_ARTICLES ({self.digest_min_articles}) dépasse "
                f"DAILY_QUOTA ({self.daily_quota}) : le plafond l'emportera."
            )
        if self.urgent_score_threshold <= self.digest_floor_score:
            warns.append(
                "URGENT_SCORE_THRESHOLD est inférieur ou égal à DIGEST_FLOOR_SCORE : "
                "presque tout deviendrait urgent, ce qui vide l'alerte de son sens."
            )
        return warns


def load_feeds(path: Path) -> list[dict]:
    """
    Charge feeds.yaml.

        feeds:
          - name: BleepingComputer
            url: https://www.bleepingcomputer.com/feed/
            enabled: true
            weight: 2
    """
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    feeds = []
    for entry in data.get("feeds", []):
        if not entry.get("enabled", True) or not entry.get("url"):
            continue
        feeds.append(
            {
                "name": entry.get("name") or entry["url"],
                "url": entry["url"],
                "weight": int(entry.get("weight", 0)),
            }
        )
    return feeds


settings = Settings()
settings.feeds = load_feeds(settings.feeds_path)
