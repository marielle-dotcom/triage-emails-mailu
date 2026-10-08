"""Accès à la base des décisions et au stockage de quarantaine (outil de quarantaine)."""

import hashlib
import os
import smtplib
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

DSN = os.environ.get("TRIAGE_DB_DSN", "")
DOSSIER = Path(os.environ.get("TRIAGE_QUARANTINE_DIR", "/quarantaine"))
REINJECT_HOST = os.environ.get("TRIAGE_REINJECT_HOST", "smtp")
REINJECT_PORT = int(os.environ.get("TRIAGE_REINJECT_PORT", "10036"))
RETENTION_QUARANTAINE_JOURS = int(os.environ.get("TRIAGE_RETENTION_QUARANTAINE_JOURS", "30"))
RETENTION_DECISIONS_JOURS = int(os.environ.get("TRIAGE_RETENTION_DECISIONS_JOURS", "180"))

# Transitions autorisées : état actuel -> {action: nouvel état}
TRANSITIONS = {
    "en_attente": {"liberer": "libere", "confirmer": "confirme"},
    "confirme": {"supprimer": "supprime"},
}


class ActionRefusee(Exception):
    pass


def connexion():
    return psycopg.connect(DSN, row_factory=dict_row)


def fichier(triage_id):
    if not triage_id.isalnum():
        raise ActionRefusee("identifiant invalide")
    return DOSSIER / f"{triage_id}.eml"


def integrite(decision):
    """« intègre », « altéré » ou « absent » : compare le fichier à l'empreinte enregistrée."""
    f = fichier(decision["triage_id"])
    if not f.exists():
        return "absent"
    return "intègre" if hashlib.sha256(f.read_bytes()).hexdigest() == decision["fichier_sha256"] else "altéré"


def entetes(triage_id, limite=20000):
    """Bloc d'en-têtes du message en quarantaine (jamais le corps)."""
    f = fichier(triage_id)
    if not f.exists():
        return ""
    brut = f.read_bytes()[:limite * 4]
    return brut.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0].decode("utf-8", errors="replace")[:limite]


def liste(etat=None, limite=500):
    requete = "SELECT * FROM decisions WHERE action = 'quarantaine'"
    params = []
    if etat:
        requete += " AND etat = %s"
        params.append(etat)
    requete += " ORDER BY recu_le DESC LIMIT %s"
    params.append(limite)
    with connexion() as cx:
        return cx.execute(requete, params).fetchall()


def decision(triage_id):
    with connexion() as cx:
        return cx.execute("SELECT * FROM decisions WHERE triage_id = %s AND action = 'quarantaine'",
                          (triage_id,)).fetchone()


def journal(triage_id=None, limite=300):
    with connexion() as cx:
        if triage_id:
            return cx.execute("SELECT * FROM journal_validation WHERE triage_id = %s ORDER BY horodatage DESC",
                              (triage_id,)).fetchall()
        return cx.execute("SELECT * FROM journal_validation ORDER BY horodatage DESC LIMIT %s", (limite,)).fetchall()


def _liberer(d):
    """Renvoie le message intact à son destinataire d'origine, sans repasser par le filtre."""
    if integrite(d) != "intègre":
        raise ActionRefusee("le fichier en quarantaine est absent ou altéré : libération refusée")
    contenu = fichier(d["triage_id"]).read_bytes()
    destinataires = [r.strip() for r in d["destinataire"].split(",") if r.strip()]
    with smtplib.SMTP(REINJECT_HOST, REINJECT_PORT, timeout=60) as client:
        refuses = client.sendmail(d["enveloppe_expediteur"] or "", destinataires, contenu)
    if refuses:
        raise ActionRefusee(f"destinataire refusé : {', '.join(refuses)}")


def appliquer(triage_id, action, utilisateur, commentaire=""):
    """Applique une action humaine (liberer, confirmer, supprimer) et la journalise."""
    with connexion() as cx:
        d = cx.execute("SELECT * FROM decisions WHERE triage_id = %s AND action = 'quarantaine' FOR UPDATE",
                       (triage_id,)).fetchone()
        if not d:
            raise ActionRefusee("message inconnu")
        nouvel_etat = TRANSITIONS.get(d["etat"], {}).get(action)
        if not nouvel_etat:
            raise ActionRefusee(f"action « {action} » impossible depuis l'état « {d['etat']} »")
        if action == "liberer":
            _liberer(d)
        cx.execute("UPDATE decisions SET etat = %s, valide_par = %s, valide_le = now() WHERE triage_id = %s",
                   (nouvel_etat, utilisateur, triage_id))
        cx.execute("INSERT INTO journal_validation (triage_id, utilisateur, action, etat_avant, etat_apres, commentaire) "
                   "VALUES (%s, %s, %s, %s, %s, %s)",
                   (triage_id, utilisateur, action, d["etat"], nouvel_etat, commentaire or None))
    if nouvel_etat in ("libere", "supprime"):
        fichier(triage_id).unlink(missing_ok=True)
    return nouvel_etat


def expirer():
    """Rétention : supprime les quarantaines trop anciennes et purge les vieilles métadonnées."""
    with connexion() as cx:
        anciennes = cx.execute(
            "SELECT triage_id, etat FROM decisions WHERE action = 'quarantaine' AND etat IN ('en_attente', 'confirme') "
            "AND recu_le < now() - make_interval(days => %s) FOR UPDATE", (RETENTION_QUARANTAINE_JOURS,)).fetchall()
        for d in anciennes:
            cx.execute("UPDATE decisions SET etat = 'expire', valide_par = 'système', valide_le = now() "
                       "WHERE triage_id = %s", (d["triage_id"],))
            cx.execute("INSERT INTO journal_validation (triage_id, utilisateur, action, etat_avant, etat_apres, commentaire) "
                       "VALUES (%s, 'système', 'expirer', %s, 'expire', %s)",
                       (d["triage_id"], d["etat"], f"rétention de {RETENTION_QUARANTAINE_JOURS} jours dépassée"))
        purgees = cx.execute("DELETE FROM decisions WHERE recu_le < now() - make_interval(days => %s)",
                             (RETENTION_DECISIONS_JOURS,)).rowcount
    for d in anciennes:
        fichier(d["triage_id"]).unlink(missing_ok=True)
    return {"quarantaines_expirees": len(anciennes), "decisions_purgees": purgees}


if __name__ == "__main__":  # python donnees.py : lancement manuel de l'expiration
    print(expirer())
