"""
Construction et envoi des embeds Discord.

Limites API : titre 256, description 4096, field 1024, footer 2048,
total 6000, 10 embeds par message.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import discord

from sources import Article
from feedback import DOWNVOTE, UPVOTE, encode_signals
from summarizer import Summary

log = logging.getLogger(__name__)

# Code couleur par sévérité, lisible en thème sombre comme clair.
SEVERITY_STYLE = {
    "Critique": (0xE01E37, "🔴"),
    "Élevé":    (0xF07C00, "🟠"),
    "Moyen":    (0xF2C14E, "🟡"),
    "Faible":   (0x4C9F70, "🟢"),
}

# Marqueurs inscrits dans le pied des en-têtes : ils permettent à state.py de
# reconstruire, depuis Discord seul, ce qui a déjà été publié aujourd'hui.
DIGEST_MARKER = "#digest"
URGENT_MARKER = "#urgent"

TITLE_LIMIT = 256
AUTHOR_LIMIT = 256
FIELD_LIMIT = 1024
SAFE_DESC_LIMIT = 1800   # notre plafond, très en dessous de celui de Discord

# Aucune mention ne sera jamais résolue par Discord depuis les messages du bot.
NO_MENTIONS = discord.AllowedMentions.none()


def _truncate(text: str, limit: int) -> str:
    """Tronque proprement sur un mot, avec une ellipse."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(" ,.;:") + "…"


def build_embed(
    article: Article, summary: Summary, urgent_reason: str | None = None
) -> discord.Embed:
    """Transforme un couple (article, résumé) en embed prêt à publier."""
    color, emoji = SEVERITY_STYLE.get(summary.severity, SEVERITY_STYLE["Moyen"])

    lines = [f"• {_truncate(b, 260)}" for b in summary.bullets]
    description = _truncate("\n".join(lines), SAFE_DESC_LIMIT)

    embed = discord.Embed(
        title=_truncate(f"{emoji} {summary.title}", TITLE_LIMIT),
        url=article.url,
        description=description,
        color=color,
        timestamp=(
            datetime.fromtimestamp(article.published_ts, tz=timezone.utc)
            if article.published_ts
            else datetime.now(tz=timezone.utc)
        ),
    )

    # author.name = source + titre d'origine. Sert aussi de clé pour
    # reconstruire l'index anti-doublons au démarrage (state.py).
    embed.set_author(name=_truncate(f"{article.source} · {article.title}", AUTHOR_LIMIT))

    embed.add_field(name="Sévérité", value=f"**{summary.severity}**", inline=True)

    # Signaux autoritatifs : ils valent plus qu'un adjectif dans un article.
    if article.kev_cves:
        embed.add_field(name="CISA KEV", value="⚠️ exploitation avérée", inline=True)
    if article.epss_max is not None and article.epss_max >= 0.01:
        embed.add_field(name="EPSS 30 j", value=f"{article.epss_max:.1%}", inline=True)

    if summary.cves:
        marked = [f"`{c}`" + ("⚠️" if c in article.kev_cves else "") for c in summary.cves]
        embed.add_field(name="CVE", value=_truncate(" · ".join(marked), FIELD_LIMIT), inline=False)

    # Une tentative d'injection détectée est signalée, jamais masquée :
    # le lecteur doit savoir que ce résumé mérite une relecture.
    if summary.injection_flags:
        embed.add_field(
            name="⚠️ Contenu suspect",
            value=_truncate(
                "Motifs d'injection de prompt détectés dans la source "
                f"({', '.join(summary.injection_flags)}). Résumé à vérifier.",
                FIELD_LIMIT,
            ),
            inline=False,
        )

    if urgent_reason:
        embed.add_field(
            name="🚨 Alerte immédiate",
            value=_truncate(urgent_reason, FIELD_LIMIT),
            inline=False,
        )

    # Signaux inscrits ici : c'est ce qui rend un vote attribuable à un
    # critère précis plutôt qu'à l'article entier.
    footer = f"Score {article.score}"
    encoded = encode_signals(getattr(article, "signals", []) or [])
    if encoded:
        footer += f" · {encoded}"
    if urgent_reason:
        footer += f" · {URGENT_MARKER}"
    if summary.tags:
        footer += " · " + " ".join(f"#{t}" for t in summary.tags)
    if summary.generated_by == "heuristique":
        footer += " · résumé sans IA"
    embed.set_footer(text=_truncate(footer, 300))

    return embed


def build_header_embed(
    count: int,
    provider: str,
    deferred: int = 0,
    urgent: bool = False,
    quota: int | None = None,
    candidates: int | None = None,
) -> discord.Embed:
    """
    En-tête récapitulatif.

    Deux formes : l'alerte immédiate, et le digest quotidien qui annonce
    combien de candidats ont été écartés — c'est cette ligne qui rend la
    sélectivité visible au lecteur.
    """
    plural = "s" if count > 1 else ""
    if urgent:
        return discord.Embed(
            title="🚨 Alerte cyber immédiate",
            description=(
                f"**{count}** vulnérabilité{plural} à exploitation avérée ou "
                "hautement probable, publiée hors du digest quotidien."
            ),
            color=0xE01E37,
            timestamp=datetime.now(tz=timezone.utc),
        ).set_footer(text=f"Résumés : {provider} · {URGENT_MARKER}")

    description = f"**{count}** article{plural} retenu{plural} aujourd'hui."
    if quota:
        description += f" Plafond quotidien : {quota}."
    if candidates and candidates > count:
        description += f"\n{candidates - count} autre(s) candidat(s) écarté(s) après arbitrage."
    if deferred:
        description += f"\n⏸️ {deferred} reporté(s) au prochain cycle (quota IA)."

    return discord.Embed(
        title="🛡️ Veille cyber — digest du jour",
        description=description,
        color=0x5865F2,
        timestamp=datetime.now(tz=timezone.utc),
    ).set_footer(text=f"Résumés : {provider} · {DIGEST_MARKER}")


async def publish(
    channel: discord.abc.Messageable,
    items: list[tuple[Article, Summary]],
    provider: str,
    deferred: int = 0,
    urgent_reasons: dict[str, str] | None = None,
    mention: str = "none",
    quota: int | None = None,
    candidates: int | None = None,
    add_vote_reactions: bool = True,
) -> list[tuple[Article, Summary]]:
    """
    Envoie les embeds et retourne **uniquement** les articles réellement
    publiés.

    C'est important : seuls ces articles doivent être marqués comme vus.
    Un embed dont l'envoi échoue doit rester candidat au cycle suivant,
    sinon il est perdu définitivement.

    Un message par article : plus lisible dans le fil, et permet de réagir
    ou d'ouvrir un fil article par article. discord.py gère lui-même le
    rate limit entre les envois.
    """
    if not items:
        return []

    from state import url_hash  # import local : évite une dépendance circulaire

    urgent_reasons = urgent_reasons or {}
    is_urgent_batch = bool(urgent_reasons)
    posted: list[tuple[Article, Summary]] = []

    # La mention n'est autorisée que pour les alertes urgentes, et seulement
    # si elle est explicitement configurée. Le digest quotidien ne notifie
    # jamais personne.
    content, allowed = None, NO_MENTIONS
    if is_urgent_batch and mention and mention.lower() != "none":
        if mention.lower() == "here":
            content, allowed = "@here", discord.AllowedMentions(everyone=True)
        elif mention.isdigit():
            content = f"<@&{mention}>"
            allowed = discord.AllowedMentions(roles=True)

    try:
        await channel.send(
            content=content,
            embed=build_header_embed(
                len(items), provider, deferred,
                urgent=is_urgent_batch, quota=quota, candidates=candidates,
            ),
            allowed_mentions=allowed,
        )
    except discord.HTTPException as exc:
        log.warning("En-tête non publié : %s", exc)

    for article, summary in items:
        try:
            reason = urgent_reasons.get(url_hash(article.url))
            message = await channel.send(
                embed=build_embed(article, summary, urgent_reason=reason),
                allowed_mentions=NO_MENTIONS,
            )
            posted.append((article, summary))
        except discord.HTTPException as exc:
            # Non marqué comme publié : il reviendra au prochain cycle.
            log.error("Échec de publication pour %s : %s", article.url, exc)
            continue

        # Réactions pré-posées : voter en un tap. Un échec n'est pas grave,
        # l'article est déjà publié.
        if add_vote_reactions:
            for emoji in (UPVOTE, DOWNVOTE):
                try:
                    await message.add_reaction(emoji)
                except discord.HTTPException as exc:
                    log.debug("Réaction %s non posée : %s", emoji, exc)
                    break  # permission manquante : inutile d'insister
    return posted
