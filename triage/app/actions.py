"""Actions par niveau décidées par le filtre (document d'architecture, §5).

- N3 et N4 : le message n'est pas livré ; il est conservé intact dans le stockage
  de quarantaine séparé (quarantaine.py), avec l'en-tête X-Original-Recipient ;
  une alerte est envoyée à l'équipe sécurité (jamais à l'expéditeur).
- N0 à N2 : livraison au destinataire ; N1 (bandeau) et N2 (dossier Suspect)
  sont appliqués plus loin, par Roundcube et par Sieve.
"""

import os
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

ALERTES_A = os.environ.get("TRIAGE_ALERT_TO", "securite@anac.lab")
ALERTES_DE = os.environ.get("TRIAGE_ALERT_FROM", "postmaster@anac.lab")
NIVEAUX_QUARANTAINE = {3, 4}


def en_quarantaine(decision):
    return decision.niveau in NIVEAUX_QUARANTAINE


def libelle_action(decision):
    """Action enregistrée en base : quarantaine (N3, N4), suspect (N2) ou livre (N0, N1)."""
    if en_quarantaine(decision):
        return "quarantaine"
    return "suspect" if decision.niveau == 2 else "livre"


def entetes_action(decision, rcpts):
    """En-têtes ajoutés en plus des 4 en-têtes de triage."""
    if en_quarantaine(decision):
        return {"X-Original-Recipient": ", ".join(rcpts)}
    return {}


def desamorcer(texte):
    """Rend les domaines et adresses non cliquables dans l'alerte : exemple[.]test, hxxp://."""
    return (texte or "").replace("http", "hxxp").replace(".", "[.]").replace("@", "[@]")


def alerte(decision, fields):
    """Message d'alerte pour l'équipe sécurité : métadonnées seulement, aucun contenu du mail."""
    critique = decision.niveau == 4
    m = EmailMessage()
    m["From"] = f"Système de triage <{ALERTES_DE}>"
    m["To"] = ALERTES_A
    m["Subject"] = ("[CRITIQUE] " if critique else "") + \
        f"[Triage N{decision.niveau}] Message mis en quarantaine ({fields.get('triage_id', '')})"
    m["Date"] = formatdate(localtime=True)
    m["Message-ID"] = make_msgid(domain=ALERTES_DE.rsplit("@", 1)[-1])
    m["Auto-Submitted"] = "auto-generated"
    lignes = [
        f"Un message a été placé en quarantaine (niveau N{decision.niveau}"
        f"{', déclencheur direct : ' + decision.declencheur_direct if decision.declencheur_direct else ''}).",
        "",
        f"Date              : {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
        f"Identifiant triage: {fields.get('triage_id', '')}",
        f"Message-ID        : {desamorcer(fields.get('message_id', ''))}",
        f"Expéditeur affiché: {desamorcer(fields.get('header_from', ''))}",
        f"Destinataire      : {desamorcer(', '.join(fields.get('rcpt_to', [])))}",
        f"Niveau / score    : N{decision.niveau} / {decision.score} sur 9",
        f"Détections        : {', '.join(decision.detections) or 'aucune'}",
        "",
        "Raisons :",
        *[f"  - {nom} : {desamorcer(raison)}" for nom, raison in fields.get("filters", {}).items()],
        "",
        "Le message est conservé intact dans le stockage de quarantaine (hors messagerie).",
        "Le valider, le libérer ou le supprimer depuis l'outil de quarantaine (machine du lab, port 8088).",
    ]
    m.set_content("\n".join(lignes) + "\n")
    return m.as_bytes().replace(b"\n", b"\r\n")
