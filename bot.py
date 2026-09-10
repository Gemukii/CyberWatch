#!/usr/bin/env python3
"""
Point d'entrée : ordonnancement, commandes slash, cycle de veille.

Un cycle collecte toujours, mais ne publie que sur urgence avérée ou à
l'heure du digest. Détail du pipeline : docs/ARCHITECTURE.md
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time

import discord
from discord import app_commands
from discord.ext import commands, tasks

import feedback as feedback_mod
import filters
import publisher
import selection
import sources
import state as state_mod
from config import settings
from enrichment import Enricher
from selection import CandidateQueue, DailyBudget
from state import State
from summarizer import Summarizer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cyberwatch")
logging.getLogger("discord").setLevel(logging.WARNING)

# Commandes slash uniquement : évite l'intent privilégiée MESSAGE CONTENT.
intents = discord.Intents.default()

bot = commands.Bot(command_prefix="!cyberwatch-unused", intents=intents, help_command=None)

state = State(retention_days=settings.retention_days)
summarizer = Summarizer(settings)
enricher = Enricher(settings)

# Empêche deux cycles simultanés (boucle auto + commande manuelle).
queue = CandidateQueue(ttl_hours=settings.candidate_ttl_hours)

# Poids appris depuis les réactions 👍/👎. Recalculés périodiquement depuis
# l'historique Discord, jamais stockés : voir feedback.py.
learned = feedback_mod.LearnedWeights(
    min_votes=settings.feedback_min_votes,
    max_adjustment=settings.feedback_max_adjustment,
)
_feedback_refreshed_at = 0.0


async def refresh_feedback(channel, force: bool = False) -> bool:
    """
    Recalcule les poids appris si le cache a expiré.

    Relire l'historique coûte des appels à l'API Discord : on ne le fait
    qu'une fois par `FEEDBACK_TTL_HOURS`, pas à chaque cycle.
    """
    global learned, _feedback_refreshed_at
    if not settings.enable_feedback or channel is None:
        return False
    if not force and (time.time() - _feedback_refreshed_at) < settings.feedback_ttl_hours * 3600:
        return False
    learned = await feedback_mod.collect_feedback(
        channel,
        lookback_days=settings.feedback_lookback_days,
        min_votes=settings.feedback_min_votes,
        max_adjustment=settings.feedback_max_adjustment,
        message_limit=settings.feedback_message_limit,
    )
    _feedback_refreshed_at = time.time()
    return True
budget = DailyBudget(
    timezone_name=settings.timezone_name,
    digest_hour=settings.digest_hour,
)

cycle_lock = asyncio.Lock()


# --- Cycle de veille ---
async def collect(report: dict) -> list:
    """
    Étape gratuite : collecte, filtre, enrichit, et alimente la file de
    candidats. Aucun appel IA ici, donc elle peut tourner toutes les heures
    sans coût.
    """
    articles, feed_results = await sources.fetch_all_feeds(
        settings.feeds, settings.max_age_hours
    )
    state.record_feed_results(feed_results)
    report["fetched"] = len(articles)

    unhealthy = state.unhealthy_feeds(settings.feed_failure_threshold)
    if unhealthy:
        log.warning("Flux en panne : %s", ", ".join(f.name for f in unhealthy))

    if not articles:
        return []

    # Pré-filtrage sur titre + résumé RSS, seuil abaissé : on garde de la
    # marge avant les étapes coûteuses en réseau.
    shortlist = filters.select_articles(
        articles,
        state,
        min_score=max(1, settings.min_score - 3),
        similarity=settings.dedup_similarity,
        limit=settings.shortlist_limit,
    )
    if not shortlist:
        return []

    if settings.fetch_fulltext:
        await sources.enrich_with_fulltext(
            shortlist, settings.user_agent, settings.http_timeout, settings.fulltext_max_chars
        )

    # Enrichissement KEV / EPSS puis re-scoring sur données complètes.
    await enricher.enrich(shortlist)
    for article in shortlist:
        article.score, article.reasons = filters.score_article(
            article, feedback=learned if settings.enable_feedback else None
        )

    retained = [a for a in shortlist if a.score >= settings.min_score]

    # Un candidat déjà en file voit son score mis à jour : une CVE peut
            # entrer au KEV entre deux cycles.
    added = 0
    for article in retained:
        if queue.add(article, state_mod.url_hash(article.url)):
            added += 1
    queue.purge(settings.candidate_ttl_hours)

    report["queued"] = added
    report["queue_size"] = len(queue)
    log.info(
        "Collecte : %d articles → %d en file (%d nouveaux, file = %d)",
        len(articles), len(retained), added, len(queue),
    )
    return retained


async def publish_selection(
    channel: discord.abc.Messageable,
    selection: list,
    report: dict,
    urgent_reasons: dict[str, str] | None = None,
    candidates: int | None = None,
) -> int:
    """
    Résume puis publie une sélection déjà arbitrée, et retire de la file
    les articles réellement publiés.
    """
    if not selection:
        return 0

    log.info("Résumé de %d article(s) via %s…", len(selection), settings.ai_provider)
    summarized, deferred = await summarizer.summarize_many(selection)
    report["deferred"] = report.get("deferred", 0) + len(deferred)

    posted = await publisher.publish(
        channel,
        summarized,
        settings.ai_provider,
        deferred=len(deferred),
        urgent_reasons=urgent_reasons,
        mention=settings.urgent_mention if urgent_reasons else "none",
        quota=None if urgent_reasons else settings.daily_quota,
        candidates=candidates,
    )

    # Seuls les articles réellement partis sont mémorisés et retirés de la
    # file. Un envoi échoué reste candidat pour le prochain arbitrage.
    for article, summary in posted:
        state.mark_published(article.url, article.title, article.source, summary.severity)
    queue.remove([state_mod.url_hash(a.url) for a, _ in posted])

    report["posted"] = report.get("posted", 0) + len(posted)
    return len(posted)


async def run_cycle(channel: discord.abc.Messageable, force_digest: bool = False) -> dict:
    """
    Un cycle complet.

    Collecte toujours ; ne publie que dans deux cas : une urgence avérée,
    ou l'heure du digest quotidien. C'est ce découplage qui permet de tenir
    2-3 articles par jour tout en surveillant les flux toutes les heures.
    """
    async with cycle_lock:
        report = {
            "fetched": 0, "queued": 0, "queue_size": 0,
            "urgent": 0, "digest": 0, "posted": 0, "deferred": 0, "error": None,
        }
        try:
            # Poids appris rafraîchis AVANT la collecte : le scoring des
            # nouveaux articles doit tenir compte des votes les plus récents.
            await refresh_feedback(channel)

            await collect(report)

            # --- Voie 1 : urgences, publiées immédiatement et hors quota ---
            if settings.enable_urgent:
                slots = budget.urgent_slots_left(settings.urgent_daily_max)
                urgent, reasons = [], {}
                if slots > 0:
                    for key, article in queue.ranked():
                        flagged, reason = selection.is_urgent(article, settings)
                        if flagged:
                            urgent.append(article)
                            reasons[key] = reason
                        if len(urgent) >= slots:
                            break
                if urgent:
                    log.warning("Publication urgente de %d article(s)", len(urgent))
                    sent = await publish_selection(channel, urgent, report, reasons)
                    budget.note_urgent(sent)
                    report["urgent"] = sent

            # --- Voie 2 : digest quotidien ---
            if force_digest or budget.digest_due():
                # Sélection relative : les N meilleurs du jour, pas ceux qui
                # dépassent une barre absolue (impossible à calibrer).
                ranked = [article for _, article in queue.ranked()]

                # Plancher bas : il n'écarte que le hors-sujet manifeste.
                pertinents = [
                    a for a in ranked if a.score >= settings.digest_floor_score
                ]
                chosen = pertinents[: settings.daily_quota]

                # Anti-silence : journée calme = veille courte, pas absente.
                # Le plafond prime toujours (min() contre un réglage incohérent).
                objectif = min(settings.digest_min_articles, settings.daily_quota)
                if len(chosen) < objectif and ranked:
                    complement = [a for a in ranked if a not in chosen]
                    manquant = objectif - len(chosen)
                    chosen += complement[:manquant]
                    if complement[:manquant]:
                        log.info(
                            "Journée calme : %d article(s) ajouté(s) sous le "
                            "plancher pour maintenir la cadence",
                            len(complement[:manquant]),
                        )

                if chosen:
                    log.info(
                        "Digest quotidien : %d article(s) retenus sur %d en file "
                        "(scores : %s)",
                        len(chosen), len(queue), [a.score for a in chosen],
                    )
                    report["digest"] = await publish_selection(
                        channel, chosen, report, candidates=len(ranked)
                    )
                else:
                    # Seul cas de silence désormais possible : file vide.
                    log.info("Digest quotidien : file vide, rien à publier.")
                budget.note_digest()

            report["queue_size"] = len(queue)
            state.log_run(**report)
            return report

        except Exception as exc:
            log.exception("Cycle en échec")
            report["error"] = f"{type(exc).__name__}: {exc}"
            state.log_run(**report)
            return report


async def resolve_channel():
    """Récupère le salon de publication (cache local, sinon appel API)."""
    channel = bot.get_channel(settings.channel_id)
    if channel is not None:
        return channel
    try:
        return await bot.fetch_channel(settings.channel_id)
    except discord.DiscordException as exc:
        log.error("Salon %s inaccessible : %s", settings.channel_id, exc)
        return None


@tasks.loop(minutes=settings.interval_minutes)
async def scheduled_watch():
    """Boucle automatique. Le premier tour part juste après la connexion."""
    channel = await resolve_channel()
    if channel is None:
        return
    await run_cycle(channel)


@scheduled_watch.before_loop
async def before_watch():
    await bot.wait_until_ready()


# --- Cycle de vie ---
@bot.event
async def setup_hook():
    """Synchronisation des commandes slash, avant la connexion au gateway."""
    if settings.guild_id:
        guild = discord.Object(id=settings.guild_id)
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
        log.info("Commandes slash synchronisées sur le serveur %s", settings.guild_id)
    else:
        await bot.tree.sync()
        log.info("Commandes slash synchronisées globalement (propagation : jusqu'à 1 h)")


@bot.event
async def on_ready():
    log.info("Connecté en tant que %s (id=%s)", bot.user, bot.user.id)

    # on_ready se redéclenche à chaque reconnexion. Tout ce qui suit doit
    # donc être idempotent — State.prime_from_channel l'est, la boucle aussi.
    if not state.primed:
        log.info(
            "Config : %d flux · %d min · IA=%s · max %d articles/cycle · rétention %d j",
            len(settings.feeds), settings.interval_minutes, settings.ai_provider,
            settings.max_articles_per_run, settings.retention_days,
        )
        channel = await resolve_channel()
        if channel is not None:
            await state.prime_from_channel(
                channel, limit=settings.history_limit, budget=budget
            )
        else:
            log.warning(
                "Salon %s introuvable : l'index démarre vide, des articles récents "
                "peuvent être republiés une fois.",
                settings.channel_id,
            )

    if not scheduled_watch.is_running():
        scheduled_watch.start()


# --- Commandes slash ---
@bot.tree.command(
    name="cyber-now",
    description="Collecte immédiate, et publie le digest du jour s'il n'est pas déjà parti",
)
@app_commands.checks.cooldown(1, 120.0)
async def cyber_now(interaction: discord.Interaction):
    if cycle_lock.locked():
        await interaction.response.send_message("⏳ Un cycle est déjà en cours.", ephemeral=True)
        return

    # Un cycle dépasse largement les 3 s accordées pour répondre.
    await interaction.response.defer(thinking=True)
    report = await run_cycle(interaction.channel)

    if report["error"]:
        message = f"❌ Erreur : `{report['error'][:300]}`"
    elif report["posted"]:
        parts = []
        if report["urgent"]:
            parts.append(f"🚨 {report['urgent']} alerte(s) urgente(s)")
        if report["digest"]:
            parts.append(f"📰 {report['digest']} article(s) au digest")
        message = "✅ " + " · ".join(parts)
        if report["deferred"]:
            message += f" · ⏸️ {report['deferred']} reporté(s), quota IA"
    else:
        message = (
            f"✅ Collecte faite : {report['fetched']} articles analysés, "
            f"{report['queue_size']} en file. "
        )
        if budget.last_digest_date == budget.today_key():
            message += "Le digest du jour est déjà parti."
        else:
            message += f"Digest prévu <t:{int(budget.next_digest_at().timestamp())}:R>."
    await interaction.followup.send(message)


@bot.tree.command(
    name="cyber-digest",
    description="Force l'envoi du digest maintenant, sans attendre l'heure prévue",
)
@app_commands.checks.cooldown(1, 300.0)
async def cyber_digest(interaction: discord.Interaction):
    """
    Utile pour tester le rendu, ou récupérer un digest après une coupure.
    Ne contourne pas le seuil de qualité : si rien ne dépasse
    DIGEST_MIN_SCORE, rien n'est publié.
    """
    if cycle_lock.locked():
        await interaction.response.send_message("⏳ Un cycle est déjà en cours.", ephemeral=True)
        return
    await interaction.response.defer(thinking=True)
    report = await run_cycle(interaction.channel, force_digest=True)

    if report["error"]:
        await interaction.followup.send(f"❌ Erreur : `{report['error'][:300]}`")
    elif report["digest"]:
        await interaction.followup.send(f"✅ Digest envoyé : {report['digest']} article(s).")
    else:
        await interaction.followup.send(
            "File vide : rien n'a encore été collecté depuis le dernier digest. "
            "Le prochain cycle de collecte la remplira."
        )


@bot.tree.command(
    name="cyber-queue",
    description="Affiche les candidats en lice pour le prochain digest",
)
async def cyber_queue(interaction: discord.Interaction):
    """Rend l'arbitrage transparent : ce qui passerait, ce qui serait écarté."""
    ranked = queue.ranked()
    if not ranked:
        await interaction.response.send_message(
            "File vide. Le prochain cycle de collecte la remplira.", ephemeral=True
        )
        return

    lines = []
    for rank, (_, article) in enumerate(ranked[:12], start=1):
        # La sélection est relative : le rang décide, pas le score absolu.
        if rank <= settings.daily_quota and article.score >= settings.digest_floor_score:
            marker = "✅"
        elif rank <= settings.digest_min_articles:
            marker = "🟨"  # repêché par la garantie anti-silence
        elif article.score >= settings.digest_floor_score:
            marker = "🔸"  # pertinent, mais hors quota
        else:
            marker = "▫️"  # sous le plancher de pertinence
        kev = " · KEV" if getattr(article, "kev_cves", None) else ""
        lines.append(f"{marker} `{article.score:>3}` {article.title[:70]}{kev}")

    embed = discord.Embed(
        title=f"🗳️ File d'attente — {len(ranked)} candidat(s)",
        description="\n".join(lines),
        color=0x5865F2,
    )
    embed.set_footer(
        text=(
            f"✅ passerait au digest (top {settings.daily_quota}) · 🟨 repêché "
            f"anti-silence · 🔸 pertinent hors quota · ▫️ sous le plancher "
            f"({settings.digest_floor_score})"
        )
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
    name="cyber-feedback",
    description="Ce que le bot a appris de tes votes 👍 / 👎",
)
async def cyber_feedback(interaction: discord.Interaction):
    """
    Transparence de la boucle d'apprentissage.

    Une pondération apprise qu'on ne peut pas inspecter est impossible à
    déboguer et impossible à faire confiance : cette commande montre
    exactement quels signaux ont été ajustés, sur quel volume de votes.
    """
    if not settings.enable_feedback:
        await interaction.response.send_message(
            "La boucle de feedback est désactivée (`ENABLE_FEEDBACK=false`).",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True, thinking=True)
    await refresh_feedback(interaction.channel, force=True)

    embed = discord.Embed(
        title="🎓 Poids appris depuis tes votes",
        color=0x5865F2,
        description=(
            f"**{learned.votes_seen}** vote(s) sur **{learned.articles_voted}** "
            f"article(s), fenêtre {settings.feedback_lookback_days} j."
        ),
    )

    if not learned.is_active:
        embed.add_field(
            name="Aucun ajustement actif",
            value=(
                f"Il faut au moins **{settings.feedback_min_votes} votes** sur un "
                "même signal avant qu'il ne soit ajusté. Réagis 👍 ou 👎 sous les "
                "articles publiés — le bot pose les deux réactions pour toi."
            ),
            inline=False,
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    signaux = learned.top_signals(8)
    if signaux:
        lignes = [
            f"`{delta:+d}` **{nom}** — {t.up}👍 / {t.down}👎"
            for nom, t, delta in signaux
        ]
        embed.add_field(name="Signaux", value="\n".join(lignes), inline=False)

    sources_ = learned.top_sources(5)
    if sources_:
        lignes = [
            f"`{delta:+d}` **{nom}** — {t.up}👍 / {t.down}👎"
            for nom, t, delta in sources_
        ]
        embed.add_field(name="Sources", value="\n".join(lignes), inline=False)

    embed.set_footer(
        text=(
            f"Ajustement borné à ±{settings.feedback_max_adjustment} par signal. "
            "Les signaux factuels (KEV, EPSS, CVE, CVSS) ne sont jamais ajustés."
        )
    )
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="cyber-status", description="État du bot et dernier cycle")
async def cyber_status(interaction: discord.Interaction):
    embed = discord.Embed(title="📊 État de la veille", color=0x5865F2)
    embed.add_field(name="Flux actifs", value=str(len(settings.feeds)), inline=True)
    embed.add_field(name="Collecte", value=f"toutes les {settings.interval_minutes} min", inline=True)
    embed.add_field(name="Moteur IA", value=settings.ai_provider, inline=True)

    # Le budget quotidien est l'information la plus utile au quotidien.
    digest_done = budget.last_digest_date == budget.today_key()
    embed.add_field(
        name="Budget du jour",
        value=(
            f"{settings.daily_quota} max à {settings.digest_hour:02d}h · "
            + ("déjà envoyé" if digest_done else f"<t:{int(budget.next_digest_at().timestamp())}:R>")
        ),
        inline=True,
    )
    embed.add_field(
        name="File d'attente",
        value=(
            f"{len(queue)} candidat(s)"
            + (f" · top {queue.top_scores(3)}" if len(queue) else "")
        ),
        inline=True,
    )
    embed.add_field(
        name="Urgences aujourd'hui",
        value=f"{budget.urgent_count_today()} / {settings.urgent_daily_max}",
        inline=True,
    )
    embed.add_field(name="CISA KEV", value=enricher.status(), inline=True)
    embed.add_field(
        name=f"Publiés ({settings.retention_days} j)",
        value=str(state.count_published(settings.retention_days)),
        inline=True,
    )
    embed.add_field(
        name="Index",
        value=f"mémoire · {state.memory_footprint()}"
        + ("" if state.primed else " · ⚠️ non amorcé"),
        inline=True,
    )
    embed.add_field(name="Uptime", value=state.uptime(), inline=True)

    unhealthy = state.unhealthy_feeds(settings.feed_failure_threshold)
    if unhealthy:
        embed.add_field(
            name="🔴 Flux en panne",
            value="\n".join(f"• {f.name} ({f.consecutive_failures} cycles)" for f in unhealthy)[:1024],
            inline=False,
        )

    last = state.last_run()
    if last:
        value = (
            f"<t:{last['started_at']}:R>\n"
            f"{last['fetched']} collectés · {last.get('queued', 0)} mis en file · "
            f"{last['posted']} publiés"
        )
        if last.get("deferred"):
            value += f" · {last['deferred']} reportés"
        if last.get("error"):
            value += f"\n⚠️ `{last['error'][:150]}`"
        embed.add_field(name="Dernier cycle", value=value, inline=False)
    else:
        embed.add_field(name="Dernier cycle", value="aucun pour l'instant", inline=False)

    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="cyber-sources", description="Flux surveillés et leur santé")
async def cyber_sources(interaction: discord.Interaction):
    lines = state.feed_report(settings.feed_failure_threshold)
    if not lines:
        lines = [f"• **{f['name']}** (poids {f['weight']}) — pas encore interrogé"
                 for f in settings.feeds]
    await interaction.response.send_message(
        embed=discord.Embed(
            title="📡 Flux surveillés",
            description="\n".join(lines)[:4000],
            color=0x5865F2,
        )
    )


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CommandOnCooldown):
        message = f"⏳ Trop rapide — réessaie dans {error.retry_after:.0f} s."
    else:
        log.error("Erreur de commande : %s", error)
        message = f"❌ `{str(error)[:300]}`"
    if interaction.response.is_done():
        await interaction.followup.send(message, ephemeral=True)
    else:
        await interaction.response.send_message(message, ephemeral=True)


# --------------------------------------------------------------------------- #
def main() -> None:
    problems = settings.validate()
    if problems:
        print("Configuration invalide :", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("\nVérifie ton fichier .env (voir .env.example).", file=sys.stderr)
        sys.exit(1)

    for warning in settings.warnings():
        log.warning(warning)

    bot.run(settings.discord_token, log_handler=None)


if __name__ == "__main__":
    main()
