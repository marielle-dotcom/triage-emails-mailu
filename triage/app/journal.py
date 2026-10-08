"""Enregistrement des décisions dans PostgreSQL (étape 5) — jamais bloquant pour le courrier.

Si la base est indisponible, la décision est ajoutée à un fichier d'attente
(une ligne JSON par décision) ; un fil d'exécution la rejoue dès que la base
répond. Le rejeu est idempotent (identifiant de triage unique).
"""

import json
import logging
import os
import threading
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

DSN = os.environ.get("TRIAGE_DB_DSN", "")
ATTENTE = Path(os.environ.get("TRIAGE_SPOOL", "/spool/decisions.jsonl"))
REJEU_SECONDES = int(os.environ.get("TRIAGE_SPOOL_RETRY", "60"))

log = logging.getLogger("triage")
_verrou = threading.Lock()

COLONNES = ("triage_id", "message_id", "expediteur_affiche", "domaine_expediteur", "enveloppe_expediteur",
            "destinataire", "spf", "dkim", "dmarc", "spam_bar", "score", "niveau", "detections", "raisons",
            "declencheur_direct", "action", "etat", "fichier_sha256", "taille")
INSERTION = (f"INSERT INTO decisions ({', '.join(COLONNES)}) "
             f"VALUES ({', '.join('%s' for _ in COLONNES)}) ON CONFLICT (triage_id) DO NOTHING")


def ligne(enregistrement):
    valeurs = [enregistrement.get(c) for c in COLONNES]
    valeurs[COLONNES.index("raisons")] = Jsonb(enregistrement.get("raisons") or {})
    return valeurs


def _inserer(enregistrements):
    with psycopg.connect(DSN, autocommit=False) as cx, cx.cursor() as cur:
        cur.executemany(INSERTION, [ligne(e) for e in enregistrements])


def enregistrer(enregistrement):
    """Insère la décision ; en cas d'échec, la met en attente. Renvoie True si elle est en base."""
    if DSN:
        try:
            _inserer([enregistrement])
            return True
        except Exception as exc:
            log.warning("base indisponible, décision mise en attente",
                        extra={"fields": {"triage_id": enregistrement["triage_id"], "erreur": str(exc)[:200]}})
    with _verrou, open(ATTENTE, "a", encoding="utf-8") as f:
        f.write(json.dumps(enregistrement, ensure_ascii=False) + "\n")
    return False


def rejouer():
    """Rejoue le fichier d'attente ; renvoie le nombre de décisions insérées."""
    if not DSN:
        return 0
    with _verrou:
        if not ATTENTE.exists() or ATTENTE.stat().st_size == 0:
            return 0
        enregistrements = [json.loads(l) for l in ATTENTE.read_text(encoding="utf-8").splitlines() if l.strip()]
        try:
            _inserer(enregistrements)
        except Exception:
            return 0
        ATTENTE.unlink()
    log.info("décisions en attente rejouées", extra={"fields": {"nombre": len(enregistrements)}})
    return len(enregistrements)


def demarrer_rejeu():
    def boucle():
        evenement = threading.Event()
        while not evenement.wait(REJEU_SECONDES):
            try:
                rejouer()
            except Exception:
                log.exception("rejeu des décisions en attente échoué")
    threading.Thread(target=boucle, name="rejeu-decisions", daemon=True).start()
