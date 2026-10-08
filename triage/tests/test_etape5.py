"""Test de bout en bout de l'étape 5 : base des décisions, quarantaine séparée, outil de quarantaine.

Vérifie :
1. une ligne en base par message, sans contenu (ni corps, ni objet) ;
2. N3/N4 dans le stockage de quarantaine séparé (empreinte SHA-256 conforme),
   rien chez le destinataire, alerte envoyée ;
3. l'outil de quarantaine : compte non autorisé refusé, libération d'un N3
   (livré intact), confirmation puis suppression d'un N4, transitions interdites
   et requêtes sans jeton anti-CSRF refusées, journal de chaque action ;
4. l'expiration après la durée de rétention ;
5. base arrêtée : courrier livré quand même, décision rejouée au retour de la base.

Usage : triage/tests/.venv/bin/python triage/tests/test_etape5.py   (depuis le dossier du dépôt)
"""

import http.cookiejar
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage
from pathlib import Path

from labsend import dkim_sign, header_block, locate, send_external

TAG = uuid.uuid4().hex[:6]
SENTINELLE = f"CORPS-SECRET-{TAG}"   # corps : ne doit apparaître ni en base ni dans l'outil
OBJET = f"OBJET-{TAG}"                 # objet : visible dans les en-têtes de l'outil, jamais en base
UI = "http://127.0.0.1:8088"
NEUTRE = f"Bonjour,\nCompte rendu de la réunion. {SENTINELLE}\n"
URGENT_LIEN = f"Compte suspendu : virement urgent aujourd'hui. https://bit.ly/3xYz {SENTINELLE}\n"
RESULTATS = []


def verifier(condition, libelle):
    RESULTATS.append(bool(condition))
    print(f"{'OK ' if condition else 'ÉCHEC'} {libelle}")


def sql(requete, base="triage"):
    return subprocess.run(["docker", "exec", "mailu-triage-db-1", "su-exec", "postgres", "psql", "-d", base, "-At",
                           "-F", "|", "-c", requete], capture_output=True, text=True).stdout.strip()


def construire(code, domaine, nom, texte, dkim, rcpts):
    m = EmailMessage()
    m["From"] = f"{nom} <contact@{domaine}>"
    m["To"] = ", ".join(rcpts)
    m["Subject"] = f"Etape 5 {code} {OBJET}"
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    m["Message-ID"] = f"<{TAG}.{code}@{domaine}>"
    m.set_content(texte)
    raw = m.as_bytes().replace(b"\n", b"\r\n")
    if dkim:
        raw = dkim_sign(raw, domaine)
    if dkim == "cassee":
        raw += b"P.S. ligne ajoutee apres la signature.\r\n"
    return raw


def envoyer(code, domaine, nom, texte, dkim, rcpts=("client@anac.lab",)):
    raw = construire(code, domaine, nom, texte, dkim, list(rcpts))
    return raw, send_external(f"contact@{domaine}", list(rcpts), raw)


def decision(code):
    ligne = sql(f"SELECT triage_id, niveau, action, etat, coalesce(fichier_sha256, '') FROM decisions "
                f"WHERE message_id = '<{TAG}.{code}@' || domaine_expediteur || '>'")
    return ligne.split("|") if ligne else None


def sha_fichier(triage_id):
    r = subprocess.run(["docker", "exec", "mailu-triage-1", "sha256sum", f"/quarantaine/{triage_id}.eml"],
                       capture_output=True, text=True)
    return r.stdout.split()[0] if r.returncode == 0 else None


class Navigateur:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(self, chemin):
        r = self.op.open(UI + chemin)
        return r.geturl(), r.read().decode()

    def jeton(self, chemin):
        return re.search(r'name="csrf" value="([^"]+)"', self.get(chemin)[1]).group(1)

    def post(self, chemin, donnees):
        r = self.op.open(UI + chemin, urllib.parse.urlencode(donnees).encode())
        return r.geturl(), r.read().decode()

    def connexion(self, email, mdp):
        return self.post("/connexion", {"email": email, "mot_de_passe": mdp, "csrf": self.jeton("/connexion")})[0]


def mot_de_passe(compte):
    texte = (Path.cwd() / "comptes-admin-client.txt").read_text(encoding="utf-8")
    return re.search(rf"{re.escape(compte)}\s*\nMot de passe : (\S+)", texte).group(1)


def main():
    # 1-2. Décisions en base et quarantaine séparée --------------------------------------------
    envois = {
        "N0": envoyer("N0", "legitime.test", "Service", NEUTRE, "ok"),
        "N2": envoyer("N2", "usurpe.test", "Service", URGENT_LIEN, None),
        "N3": envoyer("N3", "legitime-support.test", "Légitime Services", NEUTRE, "cassee"),
        "N4": envoyer("N4", "anac-lab.test", "Marie Durand", NEUTRE, "ok"),
        "EXP": envoyer("EXP", "legitime-support.test", "Légitime Services", NEUTRE, "cassee"),
    }
    verifier(all(r == "250" for _, r in envois.values()), "5 messages acceptés par Mailu")
    time.sleep(12)
    attendu = {"N0": ("0", "livre", "sans_objet"), "N2": ("2", "suspect", "sans_objet"),
               "N3": ("3", "quarantaine", "en_attente"), "N4": ("4", "quarantaine", "en_attente"),
               "EXP": ("3", "quarantaine", "en_attente")}
    ids = {}
    for code, (niveau, action, etat) in attendu.items():
        d = decision(code)
        verifier(d and tuple(d[1:4]) == (niveau, action, etat), f"{code} en base : niveau {niveau}, {action}, {etat} ({d and d[1:4]})")
        if d:
            ids[code] = d[0]
            if action == "quarantaine":
                verifier(sha_fichier(d[0]) == d[4], f"{code} : fichier en quarantaine, empreinte SHA-256 conforme")
                verifier(locate("client@anac.lab", f"{TAG}.{code}@") and
                         all(dossier.startswith("quarantaine/") for dossier, _ in locate("client@anac.lab", f"{TAG}.{code}@")),
                         f"{code} : rien dans la boîte du destinataire")
    colonnes = sql("SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name = 'decisions'")
    verifier(not re.search(r"corps|body|objet|subject|contenu", colonnes), "aucune colonne de contenu dans la table decisions")
    lignes = sql(f"SELECT d::text FROM decisions d WHERE message_id LIKE '<{TAG}.%'")
    verifier(SENTINELLE not in lignes and OBJET not in lignes, "aucun contenu du message (corps, objet) dans les lignes en base")
    alertes = locate("administrateur@anac.lab", f"{TAG}\\[\\.\\]")
    verifier(len(alertes) == 3, f"3 alertes envoyées (N3, N4, EXP) : {len(alertes)}")

    # 3. Outil de quarantaine -----------------------------------------------------------------
    intrus = Navigateur()
    verifier(intrus.connexion("client@anac.lab", mot_de_passe("client@anac.lab")).endswith("erreur=1"),
             "compte non administrateur refusé")
    verifier(intrus.get("/quarantaine")[0].endswith("/connexion"), "liste inaccessible sans connexion")
    admin = Navigateur()
    verifier(admin.connexion("administrateur@anac.lab", mot_de_passe("administrateur@anac.lab")).endswith("/quarantaine"),
             "administrateur connecté")
    liste = admin.get("/quarantaine")[1]
    verifier(all(ids[c] in liste for c in ("N3", "N4", "EXP")), "les 3 quarantaines figurent dans la liste « en attente »")
    page = admin.get(f"/quarantaine/{ids['N3']}")[1]
    verifier("intègre" in page and SENTINELLE not in page and OBJET in page,
             "page de détail : intégrité vérifiée, en-têtes affichés, corps jamais affiché")
    sans_jeton = admin.post(f"/quarantaine/{ids['N3']}/liberer", {"csrf": "faux", "commentaire": "x"})[0]
    verifier("erreur=" in sans_jeton and decision("N3")[3] == "en_attente", "requête sans jeton anti-CSRF refusée")
    interdite = admin.post(f"/quarantaine/{ids['N4']}/supprimer",
                           {"csrf": admin.jeton(f"/quarantaine/{ids['N4']}"), "commentaire": "x"})[0]
    verifier("erreur=" in interdite and decision("N4")[3] == "en_attente", "suppression refusée avant confirmation")

    admin.post(f"/quarantaine/{ids['N3']}/liberer",
               {"csrf": admin.jeton(f"/quarantaine/{ids['N3']}"), "commentaire": "faux positif (test)"})
    time.sleep(8)
    livre = [raw for dossier, raw in locate("client@anac.lab", f"{TAG}.N3@") if dossier == "INBOX"]
    corps = envois["N3"][0].replace(b"\r\n", b"\n").split(b"\n\n", 1)[1]
    verifier(decision("N3")[3] == "libere" and sha_fichier(ids["N3"]) is None, "N3 libéré : état « libéré », fichier retiré")
    verifier(len(livre) == 1 and livre[0].endswith(corps), "N3 libéré : livré une fois, intact, dans la boîte de réception")

    admin.post(f"/quarantaine/{ids['N4']}/confirmer",
               {"csrf": admin.jeton(f"/quarantaine/{ids['N4']}"), "commentaire": "usurpation confirmée (test)"})
    verifier(decision("N4")[3] == "confirme", "N4 confirmé malveillant")
    admin.post(f"/quarantaine/{ids['N4']}/supprimer",
               {"csrf": admin.jeton(f"/quarantaine/{ids['N4']}"), "commentaire": "suppression après validation (test)"})
    verifier(decision("N4")[3] == "supprime" and sha_fichier(ids["N4"]) is None, "N4 supprimé : fichier effacé")
    journal = sql(f"SELECT triage_id || ':' || action || ':' || utilisateur FROM journal_validation "
                  f"WHERE triage_id IN ('{ids['N3']}', '{ids['N4']}') ORDER BY id")
    verifier(journal.split("\n") == [f"{ids['N3']}:liberer:administrateur@anac.lab", f"{ids['N4']}:confirmer:administrateur@anac.lab",
                                     f"{ids['N4']}:supprimer:administrateur@anac.lab"], "journal : 3 actions tracées avec leur auteur")

    # 4. Expiration ---------------------------------------------------------------------------
    sql(f"UPDATE decisions SET recu_le = now() - interval '31 days' WHERE triage_id = '{ids['EXP']}'")
    sortie = subprocess.run(["docker", "exec", "mailu-triage-ui-1", "/venv/bin/python", "donnees.py"],
                            capture_output=True, text=True).stdout.strip()
    verifier(decision("EXP")[3] == "expire" and sha_fichier(ids["EXP"]) is None,
             f"quarantaine de plus de 30 jours expirée et effacée ({sortie})")

    # 5. Base arrêtée -------------------------------------------------------------------------
    subprocess.run(["docker", "compose", "stop", "triage-db"], capture_output=True)
    _, reponse = envoyer("PANNE", "legitime.test", "Service", NEUTRE, "ok")
    time.sleep(8)
    verifier(reponse == "250" and [d for d, _ in locate("client@anac.lab", f"{TAG}.PANNE@")] == ["INBOX"],
             "base arrêtée : courrier accepté et livré normalement")
    attente = subprocess.run(["docker", "exec", "mailu-triage-1", "cat", "/spool/decisions.jsonl"],
                             capture_output=True, text=True).stdout
    verifier(f"{TAG}.PANNE@" in attente, "base arrêtée : décision mise dans le fichier d'attente")
    subprocess.run(["docker", "compose", "start", "triage-db"], capture_output=True)
    for _ in range(18):  # le filtre rejoue le fichier d'attente toutes les 60 s
        time.sleep(10)
        if decision("PANNE"):
            break
    verifier(decision("PANNE") is not None, "base revenue : décision rejouée automatiquement")

    print("RÉSULTAT:", "OK" if all(RESULTATS) else "ÉCHEC", f"({sum(RESULTATS)}/{len(RESULTATS)})")
    sys.exit(0 if all(RESULTATS) else 1)


if __name__ == "__main__":
    main()
