"""Outil de quarantaine du système de triage (étape 5, document d'architecture §7).

- Accès réservé aux administrateurs listés dans TRIAGE_UI_ADMINS, authentifiés
  par leur compte Mailu (connexion IMAP) ; publié sur 127.0.0.1 uniquement.
- Affiche les métadonnées et les en-têtes, jamais le corps ni les pièces jointes.
- Actions journalisées : libérer (faux positif), confirmer malveillant, supprimer
  (seulement après confirmation) ; expiration automatique après la rétention.
"""

import html
import imaplib
import logging
import os
import secrets
import ssl
import threading
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

import donnees

ADMINS = {a.strip().lower() for a in os.environ.get("TRIAGE_UI_ADMINS", "").split(",") if a.strip()}
IMAP_HOST = os.environ.get("TRIAGE_IMAP_HOST", "front")
IMAP_PORT = int(os.environ.get("TRIAGE_IMAP_PORT", "993"))
EXPIRATION_HEURES = int(os.environ.get("TRIAGE_EXPIRATION_HEURES", "24"))
# Session : déconnexion après 15 min sans action, et au plus tard 8 h après la connexion.
# Les horodatages sont dans le cookie signé (non modifiable sans la clé) et contrôlés ici, côté serveur.
INACTIVITE_S = int(os.environ.get("TRIAGE_UI_INACTIVITE_MIN", "15")) * 60
DUREE_MAX_S = int(os.environ.get("TRIAGE_UI_DUREE_MAX_H", "8")) * 3600

LIBELLES_NIVEAU = {3: "N3 Élevé", 4: "N4 Critique"}
LIBELLES_ETAT = {"en_attente": "En attente", "confirme": "Confirmé malveillant", "libere": "Libéré",
                 "supprime": "Supprimé", "expire": "Expiré"}
LIBELLES_ACTION = {"liberer": "Libérer (faux positif)", "confirmer": "Confirmer malveillant",
                   "supprimer": "Supprimer définitivement"}

log = logging.getLogger("uvicorn.error")
app = FastAPI(title="Quarantaine du système de triage", docs_url=None, redoc_url=None, openapi_url=None)
# max_age=None : cookie de session, effacé à la fermeture du navigateur (sauf restauration de session).
app.add_middleware(SessionMiddleware, secret_key=os.environ["TRIAGE_UI_SECRET"], session_cookie="triage_session",
                   max_age=None, same_site="strict", https_only=False)

e = html.escape

STYLE = """
:root { --fond:#fcfcfb; --texte:#0b0b0b; --texte2:#52514e; --trait:#dddcd7; --accent:#2a78d6; --alerte:#d03b3b; }
@media (prefers-color-scheme: dark) { :root { --fond:#1a1a19; --texte:#fff; --texte2:#c3c2b7; --trait:#3a3a37; --accent:#3987e5; --alerte:#e66767; } }
body { font: 15px/1.45 system-ui, sans-serif; background: var(--fond); color: var(--texte); margin: 0; }
header { padding: 12px 24px; border-bottom: 1px solid var(--trait); display: flex; gap: 20px; align-items: center; }
header strong { margin-right: auto; } main { padding: 16px 24px; max-width: 1200px; }
a { color: var(--accent); } table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--trait); vertical-align: top; }
th { color: var(--texte2); font-weight: 600; } .muet { color: var(--texte2); }
pre { white-space: pre-wrap; word-break: break-all; background: rgba(127,127,127,.08); padding: 10px; font-size: 13px; }
.erreur { border-left: 4px solid var(--alerte); padding: 8px 12px; margin: 12px 0; }
.ok { border-left: 4px solid var(--accent); padding: 8px 12px; margin: 12px 0; }
form.action { display: inline-block; margin: 4px 12px 4px 0; } textarea { width: 360px; height: 3em; }
button { font: inherit; padding: 4px 12px; cursor: pointer; }
"""


def page(titre, corps, request=None, code=200):
    utilisateur = request.session.get("utilisateur") if request else None
    menu = ""
    if utilisateur:
        menu = (f'<a href="/quarantaine">En attente</a><a href="/quarantaine?etat=tous">Toutes</a>'
                f'<a href="/journal">Journal</a><span class="muet">{e(utilisateur)}</span>'
                f'<form method="post" action="/deconnexion" style="margin:0">{jeton(request)}'
                f'<button>Déconnexion</button></form>')
    return HTMLResponse(
        f'<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width, initial-scale=1"><title>{e(titre)} – Quarantaine</title>'
        f'<style>{STYLE}</style></head><body><header><strong>Quarantaine du système de triage</strong>{menu}</header>'
        f'<main><h1>{e(titre)}</h1>{corps}</main></body></html>', status_code=code,
        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
                 "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})


def jeton(request):
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return f'<input type="hidden" name="csrf" value="{e(request.session["csrf"])}">'


def jeton_valide(request, csrf):
    return bool(csrf) and secrets.compare_digest(csrf, request.session.get("csrf", ""))


def connecte(request):
    if request.session.get("utilisateur") not in ADMINS:
        return False
    maintenant = int(time.time())
    debut = request.session.get("connecte_le", 0)
    derniere = request.session.get("derniere_action", 0)
    if maintenant - derniere > INACTIVITE_S or maintenant - debut > DUREE_MAX_S:
        log.info("session expirée : %s", request.session.get("utilisateur"))
        request.session.clear()
        request.session["expiree"] = True
        return False
    request.session["derniere_action"] = maintenant
    return True


def authentifier(email, mot_de_passe):
    """Vrai si le compte est un administrateur autorisé ET que Mailu accepte son mot de passe."""
    if email not in ADMINS:
        return False
    try:
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ssl._create_unverified_context(), timeout=10)
        try:
            imap.login(email, mot_de_passe)
        finally:
            try:
                imap.logout()
            except Exception:
                pass
        return True
    except Exception:
        return False


def date(valeur):
    return valeur.strftime("%Y-%m-%d %H:%M") if valeur else ""


@app.get("/sante")
def sante():
    return {"etat": "ok"}


@app.get("/connexion", response_class=HTMLResponse)
def formulaire_connexion(request: Request, erreur: str = ""):
    msg = '<p class="erreur">Identifiants refusés ou compte non autorisé.</p>' if erreur else ""
    if request.session.pop("expiree", False):
        msg += '<p class="erreur">Session expirée : veuillez vous reconnecter.</p>'
    return page("Connexion", f'{msg}<p class="muet">Réservé à l\'équipe sécurité (compte administrateur Mailu).</p>'
                f'<form method="post" action="/connexion">{jeton(request)}'
                f'<p><label>Adresse<br><input name="email" type="email" required autofocus></label></p>'
                f'<p><label>Mot de passe<br><input name="mot_de_passe" type="password" required></label></p>'
                f'<button>Se connecter</button></form>', request)


@app.post("/connexion")
def connexion(request: Request, email: str = Form(...), mot_de_passe: str = Form(...), csrf: str = Form("")):
    email = email.strip().lower()
    if jeton_valide(request, csrf) and authentifier(email, mot_de_passe):
        request.session.clear()
        request.session["utilisateur"] = email
        request.session["connecte_le"] = request.session["derniere_action"] = int(time.time())
        log.info("connexion réussie : %s", email)
        return RedirectResponse("/quarantaine", status_code=303)
    log.warning("connexion refusée : %s", email)
    return RedirectResponse("/connexion?erreur=1", status_code=303)


@app.post("/deconnexion")
def deconnexion(request: Request, csrf: str = Form("")):
    if jeton_valide(request, csrf):
        request.session.clear()
    return RedirectResponse("/connexion", status_code=303)


@app.get("/")
def accueil():
    return RedirectResponse("/quarantaine", status_code=303)


@app.get("/quarantaine", response_class=HTMLResponse)
def liste(request: Request, etat: str = "en_attente"):
    if not connecte(request):
        return RedirectResponse("/connexion", status_code=303)
    lignes = donnees.liste(None if etat == "tous" else etat)
    corps = "".join(
        f'<tr><td>{date(d["recu_le"])}</td><td>{e(LIBELLES_NIVEAU.get(d["niveau"], str(d["niveau"])))}</td>'
        f'<td>{d["score"]}/9</td><td>{e(d["expediteur_affiche"] or "")}</td><td>{e(d["destinataire"])}</td>'
        f'<td>{e(", ".join(d["detections"]))}</td><td>{e(LIBELLES_ETAT.get(d["etat"], d["etat"]))}</td>'
        f'<td><a href="/quarantaine/{e(d["triage_id"])}">Détails</a></td></tr>' for d in lignes)
    titre = "Quarantaine – en attente de validation" if etat == "en_attente" else "Quarantaine – tous les messages"
    if not lignes:
        return page(titre, '<p class="muet">Aucun message.</p>', request)
    return page(titre, f'<p class="muet">{len(lignes)} message(s).</p><table><thead><tr><th>Reçu le</th><th>Niveau</th>'
                f'<th>Score</th><th>Expéditeur affiché</th><th>Destinataire</th><th>Détections</th><th>État</th><th></th>'
                f'</tr></thead><tbody>{corps}</tbody></table>', request)


@app.get("/quarantaine/{triage_id}", response_class=HTMLResponse)
def detail(request: Request, triage_id: str, message: str = "", erreur: str = ""):
    if not connecte(request):
        return RedirectResponse("/connexion", status_code=303)
    d = donnees.decision(triage_id) if triage_id.isalnum() else None
    if not d:
        return page("Message introuvable", '<p><a href="/quarantaine">Retour</a></p>', request, 404)
    integrite = donnees.integrite(d) if d["etat"] in ("en_attente", "confirme") else "fichier supprimé"
    meta = [("Identifiant", d["triage_id"]), ("Reçu le", date(d["recu_le"])),
            ("Niveau / score", f'{LIBELLES_NIVEAU.get(d["niveau"], d["niveau"])} – {d["score"]}/9'),
            ("Déclencheur direct", d["declencheur_direct"] or "aucun"), ("État", LIBELLES_ETAT.get(d["etat"], d["etat"])),
            ("Expéditeur affiché", d["expediteur_affiche"] or ""), ("Expéditeur (enveloppe)", d["enveloppe_expediteur"] or ""),
            ("Destinataire", d["destinataire"]), ("Message-ID", d["message_id"] or ""),
            ("SPF / DKIM / DMARC", f'{d["spf"]} / {d["dkim"]} / {d["dmarc"]}'), ("Score Rspamd", d["spam_bar"] or ""),
            ("Intégrité (SHA-256)", f'{integrite} – {d["fichier_sha256"] or ""}'), ("Taille", f'{d["taille"] or 0} octets'),
            ("Validé par", f'{d["valide_par"] or ""} {date(d["valide_le"])}')]
    corps = ""
    if message:
        corps += f'<p class="ok">{e(message)}</p>'
    if erreur:
        corps += f'<p class="erreur">{e(erreur)}</p>'
    corps += "<table>" + "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in meta) + "</table>"
    corps += "<h2>Raisons</h2><table>" + "".join(
        f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in (d["raisons"] or {}).items()) + "</table>"
    actions = donnees.TRANSITIONS.get(d["etat"], {})
    if actions:
        corps += "<h2>Décision</h2>" + "".join(
            f'<form class="action" method="post" action="/quarantaine/{e(triage_id)}/{a}">{jeton(request)}'
            f'<textarea name="commentaire" placeholder="Commentaire (motif de la décision)"></textarea><br>'
            f'<button>{e(LIBELLES_ACTION[a])}</button></form>' for a in actions)
    corps += ("<h2>En-têtes du message</h2><p class=\"muet\">Le corps et les pièces jointes ne sont jamais affichés.</p>"
              f"<pre>{e(donnees.entetes(triage_id)) or 'Fichier supprimé.'}</pre>")
    historique = donnees.journal(triage_id)
    if historique:
        corps += "<h2>Journal</h2><table><tr><th>Date</th><th>Utilisateur</th><th>Action</th><th>Commentaire</th></tr>" + "".join(
            f'<tr><td>{date(j["horodatage"])}</td><td>{e(j["utilisateur"])}</td>'
            f'<td>{e(j["action"])} ({e(j["etat_avant"] or "")} → {e(j["etat_apres"] or "")})</td>'
            f'<td>{e(j["commentaire"] or "")}</td></tr>' for j in historique) + "</table>"
    return page(f"Message {triage_id}", corps, request)


@app.post("/quarantaine/{triage_id}/{action}")
def agir(request: Request, triage_id: str, action: str, csrf: str = Form(""), commentaire: str = Form("")):
    if not connecte(request):
        return RedirectResponse("/connexion", status_code=303)
    if not jeton_valide(request, csrf) or action not in LIBELLES_ACTION:
        return RedirectResponse(f"/quarantaine/{triage_id}?erreur=Requête+refusée", status_code=303)
    try:
        etat = donnees.appliquer(triage_id, action, request.session["utilisateur"], commentaire.strip()[:1000])
        log.info("quarantaine %s : %s par %s -> %s", triage_id, action, request.session["utilisateur"], etat)
        return RedirectResponse(f"/quarantaine/{triage_id}?message=Action+enregistrée+:+{etat}", status_code=303)
    except donnees.ActionRefusee as exc:
        return RedirectResponse(f"/quarantaine/{triage_id}?erreur={e(str(exc))}", status_code=303)
    except Exception:
        log.exception("action %s sur %s échouée", action, triage_id)
        return RedirectResponse(f"/quarantaine/{triage_id}?erreur=Erreur+interne,+action+non+appliquée",
                                status_code=303)


@app.get("/journal", response_class=HTMLResponse)
def journal(request: Request):
    if not connecte(request):
        return RedirectResponse("/connexion", status_code=303)
    lignes = donnees.journal()
    corps = "".join(
        f'<tr><td>{date(j["horodatage"])}</td><td><a href="/quarantaine/{e(j["triage_id"])}">{e(j["triage_id"])}</a></td>'
        f'<td>{e(j["utilisateur"])}</td><td>{e(j["action"])}</td><td>{e(j["etat_avant"] or "")} → {e(j["etat_apres"] or "")}</td>'
        f'<td>{e(j["commentaire"] or "")}</td></tr>' for j in lignes)
    return page("Journal des validations", '<table><tr><th>Date</th><th>Message</th><th>Utilisateur</th><th>Action</th>'
                f'<th>État</th><th>Commentaire</th></tr>{corps}</table>' if lignes else '<p class="muet">Vide.</p>', request)


def _expiration_periodique():
    while True:
        try:
            log.info("expiration : %s", donnees.expirer())
        except Exception:
            log.exception("expiration échouée")
        threading.Event().wait(EXPIRATION_HEURES * 3600)


@app.on_event("startup")
def demarrage():
    threading.Thread(target=_expiration_periodique, name="expiration", daemon=True).start()
