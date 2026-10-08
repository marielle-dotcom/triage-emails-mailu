"""Test de bout en bout de l'étape 3a (3 filtres, score, niveau, en-têtes).

Chaque scénario part de l'expéditeur de test externe (10.99.0.10) et l'on
vérifie dans la boîte du destinataire les en-têtes posés par le filtre :
un seul exemplaire de chaque, avec le niveau et le score attendus.

Usage : triage/tests/.venv/bin/python triage/tests/test_etape3a.py   (depuis le dossier du dépôt)
"""

import io
import re
import sys
import time
import uuid
import zipfile
from email.message import EmailMessage

from labsend import delivered, dkim_sign, header_block, send_external

RCPT = "client@anac.lab"
TAG = uuid.uuid4().hex[:6]
NEUTRE = "Bonjour,\nVeuillez trouver ci-joint le compte rendu de la réunion.\nCordialement.\n"
PHISHING = "Votre compte est suspendu. Effectuez le virement sous 24h : https://bit.ly/3xYz\n"


def zip_avec(*noms):
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w") as z:
        for nom in noms:
            z.writestr(nom, b"contenu de test")
    return tampon.getvalue()


# (nom, domaine, objet, texte, pièces jointes, en-têtes forgés, niveau, score, détections attendues)
SCENARIOS = [
    ("légitime, rien à signaler", "legitime.test", "Compte rendu", NEUTRE, [], [],
     0, 0, []),
    ("légitime + double extension .pdf.html", "legitime.test", "Facture", NEUTRE,
     [("facture.pdf.html", b"<html>faux portail</html>")], [],
     1, 1, ["suspicious_attachment"]),
    ("SPF/DMARC en échec + urgence + lien raccourci", "usurpe.test", "URGENT", PHISHING, [], [],
     2, 4, ["spf", "dmarc", "urgency_keywords", "masked_links"]),
    ("échecs + 3 filtres Python", "usurpe.test", "URGENT", PHISHING,
     [("releve.pdf.html", b"<html>x</html>")], [],
     3, 5, ["spf", "dmarc", "urgency_keywords", "masked_links", "suspicious_attachment"]),
    ("en-têtes de triage forgés à 0", "usurpe.test", "URGENT", PHISHING, [],
     [("X-Risk-Level", "0"), ("X-Phishing-Score", "0"), ("X-Warning-Banner", "false")],
     2, 4, ["spf", "dmarc", "urgency_keywords", "masked_links"]),
]


def construire(i, dom, objet, texte, pieces, forges):
    m = EmailMessage()
    m["From"] = f"Service <contact@{dom}>"
    m["To"] = RCPT
    m["Subject"] = f"{objet} [{TAG}#{i}]"
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    m["Message-ID"] = f"<{TAG}.{i}@{dom}>"
    for nom, valeur in forges:
        m[nom] = valeur
    m.set_content(texte)
    for nom, donnees in pieces:
        m.add_attachment(donnees, maintype="application", subtype="octet-stream", filename=nom)
    raw = m.as_bytes().replace(b"\n", b"\r\n")
    return dkim_sign(raw, dom) if dom == "legitime.test" else raw


def entetes_triage(hdrs):
    return {nom: re.findall(rf"^{nom}: (.*)$", hdrs, re.M | re.I)
            for nom in ("X-Risk-Level", "X-Phishing-Score", "X-Detection-Type", "X-Warning-Banner")}


def main():
    envois = []
    for i, (nom, dom, objet, texte, pieces, forges, *_attendu) in enumerate(SCENARIOS):
        reponse = send_external(f"contact@{dom}", [RCPT], construire(i, dom, objet, texte, pieces, forges))
        envois.append(reponse)
    time.sleep(10)

    ok_total = True
    for i, ((nom, dom, *_ , niveau, score, detections), reponse) in enumerate(zip(SCENARIOS, envois)):
        problemes = []
        if reponse != "250":
            problemes.append(f"réponse SMTP {reponse}")
        boites = delivered(RCPT, f"{TAG}.{i}@")
        if len(boites) != 1:
            problemes.append(f"{len(boites)} exemplaire(s) livré(s)")
            vus = {}
        else:
            vus = entetes_triage(header_block(boites[0]))
            for entete, valeurs in vus.items():
                if len(valeurs) != 1:
                    problemes.append(f"{entete} présent {len(valeurs)} fois")
            attendu = {"X-Risk-Level": [str(niveau)], "X-Phishing-Score": [str(score)],
                       "X-Detection-Type": [",".join(detections) or "none"],
                       "X-Warning-Banner": ["true" if niveau == 1 else "false"]}
            for entete, valeur in attendu.items():
                if vus.get(entete) != valeur:
                    problemes.append(f"{entete}={vus.get(entete)} au lieu de {valeur}")
        resume = " ".join(f"{k.split('-', 1)[1]}={v[0] if v else '?'}" for k, v in vus.items())
        print(f"{'OK ' if not problemes else 'ÉCHEC'} #{i} {nom} [{resume}]"
              + ("" if not problemes else " — " + "; ".join(problemes)))
        ok_total &= not problemes

    # Observation : un exécutable caché dans un zip arrive-t-il jusqu'au filtre ?
    raw = construire(99, "legitime.test", "Documents", NEUTRE, [("documents.zip", zip_avec("lisez-moi.txt", "scan.js"))], [])
    reponse = send_external("contact@legitime.test", [RCPT], raw)
    print(f"INFO zip contenant scan.js : réponse SMTP {reponse}"
          + (" (rejeté par Rspamd avant le filtre)" if reponse != "250" else " (accepté, voir X-Detection-Type dans la boîte)"))

    print("RÉSULTAT:", "OK" if ok_total else "ÉCHEC")
    sys.exit(0 if ok_total else 1)


if __name__ == "__main__":
    main()
