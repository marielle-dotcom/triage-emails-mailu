"""Test de bout en bout de l'étape 4 : actions par niveau.

Vérifie, pour des mails envoyés depuis l'expéditeur externe (10.99.0.10) :
- N0/N1 dans la boîte de réception (N1 avec X-Warning-Banner: true) ;
- N2 dans le dossier Suspect ;
- N3/N4 dans la boîte de quarantaine (dossiers N3/N4), message intact, avec
  X-Original-Recipient, rien chez le destinataire, alerte à l'équipe sécurité ;
- un N3 adressé à deux destinataires : deux quarantaines distinctes ;
- un X-Original-Recipient forgé par l'expéditeur : remplacé.

Usage : triage/tests/.venv/bin/python triage/tests/test_etape4.py   (depuis le dossier du dépôt)
"""

import re
import sys
import time
import uuid
from email.message import EmailMessage

from labsend import dkim_sign, header_block, locate, send_external

TAG = uuid.uuid4().hex[:6]
NEUTRE = "Bonjour,\nVoici le compte rendu de la réunion de mardi.\nCordialement.\n"
URGENT_LIEN = "Compte suspendu : merci d'effectuer le virement urgent aujourd'hui.\nFormulaire : https://bit.ly/3xYz\n"
ALERTES = "administrateur@anac.lab"  # destination de l'alias securite@anac.lab

# (code, scénario, domaine, nom affiché, texte, DKIM, pièce, destinataires, en-têtes forgés, niveau, dossier attendu)
SCENARIOS = [
    ("A", "N0 légitime", "legitime.test", "Service", NEUTRE, "ok", None, ["client@anac.lab"], [], 0, "INBOX"),
    ("B", "N1 double extension", "legitime.test", "Service", NEUTRE, "ok", ("facture.pdf.html", b"<html>"),
     ["client@anac.lab"], [], 1, "INBOX"),
    ("C", "N2 échecs + urgence + lien", "usurpe.test", "Service", URGENT_LIEN, None, None,
     ["client@anac.lab"], [], 2, "Suspect"),
    ("D", "N3 3 échecs + typosquatting + nom affiché", "legitime-support.test", "Légitime Services", NEUTRE,
     "cassee", None, ["client@anac.lab"], [], 3, "quarantaine/N3"),
    ("E", "N4 dirigeant + domaine typosquatté", "anac-lab.test", "Marie Durand", NEUTRE, "ok", None,
     ["client@anac.lab"], [], 4, "quarantaine/N4"),
    ("F", "N3 vers deux destinataires", "legitime-support.test", "Légitime Services", NEUTRE, "cassee", None,
     ["client@anac.lab", "user@anac.lab"], [], 3, "quarantaine/N3"),
    ("G", "N3 avec X-Original-Recipient forgé", "legitime-support.test", "Légitime Services", NEUTRE, "cassee", None,
     ["client@anac.lab"], [("X-Original-Recipient", "pirate@evil.test")], 3, "quarantaine/N3"),
]


def construire(code, domaine, nom, texte, dkim, piece, rcpts, forges):
    m = EmailMessage()
    m["From"] = f"{nom} <contact@{domaine}>"
    m["To"] = ", ".join(rcpts)
    m["Subject"] = f"Etape 4 {code} [{TAG}]"
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    m["Message-ID"] = f"<{TAG}.{code}@{domaine}>"
    for k, v in forges:
        m[k] = v
    m.set_content(texte)
    if piece:
        m.add_attachment(piece[1], maintype="application", subtype="octet-stream", filename=piece[0])
    raw = m.as_bytes().replace(b"\n", b"\r\n")
    if dkim:
        raw = dkim_sign(raw, domaine)
    if dkim == "cassee":
        raw += b"P.S. ligne ajoutee apres la signature.\r\n"
    return raw


def entete(raw, nom):
    return re.findall(rf"^{nom}: (.*)$", header_block(raw), re.M | re.I)


def main():
    envoyes = {}
    for code, _, domaine, nom, texte, dkim, piece, rcpts, forges, *_ in SCENARIOS:
        raw = construire(code, domaine, nom, texte, dkim, piece, rcpts, forges)
        envoyes[code] = (raw, send_external(f"contact@{domaine}", rcpts, raw))
    time.sleep(12)

    ok_total = True
    for code, scenario, *_, rcpts, forges, niveau, dossier in SCENARIOS:
        raw, reponse = envoyes[code]
        problemes = []
        if reponse != "250":
            problemes.append(f"réponse SMTP {reponse}")
        for rcpt in rcpts:
            trouves = locate(rcpt, f"{TAG}.{code}@")
            if [d for d, _ in trouves] != [dossier]:
                problemes.append(f"{rcpt} : trouvé dans {[d for d, _ in trouves] or 'aucun dossier'}, attendu {dossier}")
                continue
            livre = trouves[0][1]
            if entete(livre, "X-Risk-Level") != [str(niveau)]:
                problemes.append(f"X-Risk-Level={entete(livre, 'X-Risk-Level')}")
            if niveau == 1 and entete(livre, "X-Warning-Banner") != ["true"]:
                problemes.append("bandeau absent")
            if dossier.startswith("quarantaine"):
                if entete(livre, "X-Original-Recipient") != [rcpt]:
                    problemes.append(f"X-Original-Recipient={entete(livre, 'X-Original-Recipient')}")
                corps = raw.replace(b"\r\n", b"\n").split(b"\n\n", 1)[1]
                if not livre.endswith(corps):
                    problemes.append("message modifié en quarantaine")
        # Dans l'alerte, le Message-ID est désamorcé : <TAG[.]code[@]domaine> (motif grep échappé).
        alertes = locate(ALERTES, f"{TAG}\\[\\.\\]{code}\\[@\\]")
        if niveau >= 3:
            if len(alertes) != len(rcpts):
                problemes.append(f"{len(alertes)} alerte(s) au lieu de {len(rcpts)}")
            for _, a in alertes:
                sujet = entete(a, "Subject")[0] if entete(a, "Subject") else ""
                if not sujet.startswith("[CRITIQUE] [Triage N4]" if niveau == 4 else "[Triage N3]"):
                    problemes.append(f"objet d'alerte inattendu : {sujet}")
                if b"http" in a.split(b"\n\n", 1)[1] or b"bit.ly" in a:
                    problemes.append("l'alerte contient un lien")
        elif alertes:
            problemes.append(f"{len(alertes)} alerte(s) pour un N{niveau}")
        print(f"{'OK ' if not problemes else 'ÉCHEC'} {code} {scenario} → {dossier}"
              + (f" + {len(alertes)} alerte(s)" if alertes else "")
              + ("" if not problemes else " — " + "; ".join(problemes)))
        ok_total &= not problemes
    print("RÉSULTAT:", "OK" if ok_total else "ÉCHEC")
    sys.exit(0 if ok_total else 1)


if __name__ == "__main__":
    main()
