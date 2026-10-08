"""Filtre de contenu After-Queue pour Mailu.

Postfix transmet chaque message accepté sur le port 25 à ce serveur
(content_filter). Le filtre le réinjecte dans Postfix sur le port de
réinjection, qui n'applique ni milter ni content_filter.

Étape 1 : réinjection transparente.
Étape 2 : suppression des en-têtes de triage forgés par l'expéditeur et
lecture des verdicts natifs (SPF, DKIM, DMARC, antivirus, spam), journalisés.
Étape 3a : filtres Python, score sur 9, niveau N0 à N4 et ajout des en-têtes
X-Risk-Level, X-Phishing-Score, X-Detection-Type, X-Warning-Banner.
Étape 3b : les 6 filtres et le déclencheur direct « usurpation d'un dirigeant ».
Étape 4 : actions par niveau ; alerte à l'équipe sécurité pour N3/N4.
Étape 5 : N3/N4 conservés dans le stockage de quarantaine séparé (plus de
réinjection), chaque décision enregistrée dans PostgreSQL sans jamais bloquer
le courrier (fichier d'attente rejoué si la base est indisponible).

Règles de réponse (document d'architecture, §2.1) :
- 250 seulement après réinjection réussie ;
- 451 sur toute erreur interne : Postfix garde le message et réessaie ;
- jamais de 5xx pour un message venant de Postfix (pas de backscatter).
"""

import asyncio
import json
import logging
import os
import smtplib
import socket
import sys
import time
import uuid

from aiosmtpd.controller import Controller

import actions
import filtres
import journal
import quarantaine
from filtres import dirigeant
from headers import ajouter_entetes, parse_headers, strip_headers
from message import lire_message
from referentiels import charger
from score import decider
from verdicts import read_native_verdicts

LISTEN_HOST = os.environ.get("TRIAGE_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("TRIAGE_LISTEN_PORT", "10035"))
REINJECT_HOST = os.environ.get("TRIAGE_REINJECT_HOST", "smtp")
REINJECT_PORT = int(os.environ.get("TRIAGE_REINJECT_PORT", "10036"))
# Seuls ces hôtes (noms Docker) peuvent soumettre des messages au filtre.
ALLOWED_PEERS = [h for h in os.environ.get("TRIAGE_ALLOWED_PEERS", "smtp").split(",") if h]
# Un peu au-dessus de MESSAGE_SIZE_LIMIT de Mailu (50 Mo) pour ne jamais refuser
# un message que Postfix a déjà accepté.
DATA_SIZE_LIMIT = int(os.environ.get("TRIAGE_DATA_SIZE_LIMIT", "60000000"))
REINJECT_TIMEOUT = int(os.environ.get("TRIAGE_REINJECT_TIMEOUT", "60"))


class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


log = logging.getLogger("triage")


def setup_logging():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    log.addHandler(handler)
    log.setLevel(os.environ.get("TRIAGE_LOG_LEVEL", "INFO"))


def allowed_ips():
    ips = set()
    for host in ALLOWED_PEERS:
        try:
            ips.update(info[4][0] for info in socket.getaddrinfo(host, None))
        except socket.gaierror:
            log.warning("peer autorisé introuvable", extra={"fields": {"host": host}})
    return ips


def reinject(envelope, content, rcpts):
    """Renvoie `content` à Postfix (le message d'origine, moins les en-têtes retirés)."""
    mail_options = [o for o in envelope.mail_options if o.upper().startswith(("BODY=", "SMTPUTF8"))]
    with smtplib.SMTP(REINJECT_HOST, REINJECT_PORT, timeout=REINJECT_TIMEOUT) as client:
        refused = client.sendmail(
            envelope.mail_from,
            rcpts,
            content,
            mail_options=mail_options,
        )
    return refused


def send_alert(message):
    """Alerte à l'équipe sécurité, par le port de réinjection (pas d'analyse, alias développés)."""
    with smtplib.SMTP(REINJECT_HOST, REINJECT_PORT, timeout=REINJECT_TIMEOUT) as client:
        client.sendmail(actions.ALERTES_DE, [actions.ALERTES_A], message)


class TriageHandler:
    def __init__(self):
        # Listes de référence (triage/referentiels/*.yaml), lues au démarrage.
        self.referentiels = charger()

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        peer_ip = session.peer[0]
        if peer_ip not in allowed_ips():
            log.warning("connexion refusée", extra={"fields": {"peer": peer_ip}})
            return "554 5.7.1 Access denied"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        triage_id = uuid.uuid4().hex[:12]
        fields = {
            "triage_id": triage_id,
            "mail_from": envelope.mail_from,
            "rcpt_to": envelope.rcpt_tos,
            "size": len(envelope.original_content or b""),
        }
        try:
            content, removed = strip_headers(envelope.original_content)
            verdicts = read_native_verdicts(content)
            hdrs = parse_headers(content)
            fields["message_id"] = str(hdrs.get("Message-ID", "")).strip()
            fields["header_from"] = str(hdrs.get("From", "")).strip()
            message = lire_message(content)
            resultats = filtres.executer(message, self.referentiels)
            declencheurs = ["virus"] if verdicts.virus else []
            if dirigeant.declenche(message, resultats, self.referentiels):
                declencheurs.append(dirigeant.NOM)
            decision = decider(verdicts, resultats, declencheurs)
            content = ajouter_entetes(content, {**decision.entetes(),
                                                **actions.entetes_action(decision, envelope.rcpt_tos)})
        except Exception:
            log.exception("analyse échouée, 451", extra={"fields": fields})
            return "451 4.3.0 Triage temporarily unavailable, try again later"
        fields["forged_headers_removed"] = removed
        fields["native"] = verdicts.as_log()
        fields["filters"] = {r.nom: r.raison for r in resultats if r.declenche}
        fields["decision"] = {"score": decision.score, "level": decision.niveau,
                              "detections": decision.detections, "banner": decision.bandeau}
        fields["action"] = actions.libelle_action(decision)
        sha256 = None
        if actions.en_quarantaine(decision):
            # 250 seulement après un stockage réussi (§2.1) ; sinon Postfix réessaie.
            try:
                sha256 = await asyncio.to_thread(quarantaine.stocker, triage_id, content)
            except Exception:
                log.exception("mise en quarantaine échouée, 451", extra={"fields": fields})
                return "451 4.3.0 Triage temporarily unavailable, try again later"
            fields["quarantine_sha256"] = sha256
        else:
            try:
                refused = await asyncio.to_thread(reinject, envelope, content, envelope.rcpt_tos)
            except Exception:
                log.exception("réinjection échouée, 451", extra={"fields": fields})
                return "451 4.3.0 Triage temporarily unavailable, try again later"
            if refused:
                # Un destinataire refusé à la réinjection : on demande à Postfix de
                # réessayer plutôt que de perdre le message.
                fields["refused"] = {k: [v[0], v[1].decode(errors="replace")] for k, v in refused.items()}
                log.error("destinataire refusé à la réinjection, 451", extra={"fields": fields})
                return "451 4.3.0 Reinjection partially refused, try again later"
        if actions.en_quarantaine(decision):
            # L'alerte ne conditionne jamais la quarantaine : un échec est journalisé.
            try:
                await asyncio.to_thread(send_alert, actions.alerte(decision, fields))
                fields["alert_sent"] = True
            except Exception:
                fields["alert_sent"] = False
                log.exception("alerte non envoyée", extra={"fields": {"triage_id": triage_id}})
        enregistrement = {
            "triage_id": triage_id, "message_id": fields["message_id"],
            "expediteur_affiche": fields["header_from"], "domaine_expediteur": message.domaine,
            "enveloppe_expediteur": envelope.mail_from, "destinataire": ", ".join(envelope.rcpt_tos),
            "spf": verdicts.spf, "dkim": verdicts.dkim, "dmarc": verdicts.dmarc, "spam_bar": verdicts.spam_bar,
            "score": decision.score, "niveau": decision.niveau, "detections": decision.detections,
            "raisons": fields["filters"], "declencheur_direct": decision.declencheur_direct or None,
            "action": fields["action"], "etat": "en_attente" if sha256 else "sans_objet",
            "fichier_sha256": sha256, "taille": len(content),
        }
        fields["db"] = await asyncio.to_thread(journal.enregistrer, enregistrement)
        log.info("message mis en quarantaine" if sha256 else "message réinjecté", extra={"fields": fields})
        return "250 2.0.0 OK triage " + triage_id


def main():
    setup_logging()
    journal.rejouer()
    journal.demarrer_rejeu()
    handler = TriageHandler()
    controller = Controller(
        handler,
        hostname=LISTEN_HOST,
        port=LISTEN_PORT,
        server_hostname="triage",
        server_kwargs={"data_size_limit": DATA_SIZE_LIMIT, "enable_SMTPUTF8": True},
    )
    controller.start()
    log.info(
        "filtre démarré",
        extra={"fields": {"listen": f"{LISTEN_HOST}:{LISTEN_PORT}", "reinject": f"{REINJECT_HOST}:{REINJECT_PORT}"}},
    )
    try:
        asyncio.run(asyncio.Event().wait())
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
