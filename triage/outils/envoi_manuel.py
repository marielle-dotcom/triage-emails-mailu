"""Envoi d'un message de chaque niveau (N0 à N4) pour la vérification manuelle.

Les messages partent de l'expéditeur externe du lab (10.99.0.10), comme les tests,
vers client@anac.lab. Scénarios repris de tests/test_etape4.py (barème binaire).
Rien n'est vérifié ici : on contrôle ensuite à la main dans le webmail, l'outil de
quarantaine, la boîte de l'équipe sécurité et Grafana.

Usage : triage/tests/.venv/bin/python triage/outils/envoi_manuel.py   (depuis le dossier du dépôt)
"""

import sys
import time
import uuid
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from labsend import dkim_sign, send_external  # noqa: E402

TAG = uuid.uuid4().hex[:6]
DESTINATAIRE = "client@anac.lab"
NEUTRE = "Bonjour,\nVoici le compte rendu de la réunion de mardi.\nCordialement.\n"
URGENT_LIEN = "Compte suspendu : merci d'effectuer le virement urgent aujourd'hui.\nFormulaire : https://bit.ly/3xYz\n"

# (niveau, scénario, domaine, nom affiché, texte, DKIM, pièce jointe, où le trouver)
SCENARIOS = [
    (0, "légitime", "legitime.test", "Service", NEUTRE, "ok", None,
     "webmail de client@ : Boîte de réception, sans bandeau"),
    (1, "double extension", "legitime.test", "Service", NEUTRE, "ok", ("facture.pdf.html", b"<html>"),
     "webmail de client@ : Boîte de réception, bandeau « Prudence »"),
    (2, "échecs SPF/DMARC + urgence + lien raccourci", "usurpe.test", "Service", URGENT_LIEN, None, None,
     "webmail de client@ : dossier Suspect"),
    (3, "3 échecs + typosquatting + nom affiché", "legitime-support.test", "Légitime Services", NEUTRE,
     "cassee", None, "outil de quarantaine (rien chez client@) + alerte [Triage N3] chez administrateur@"),
    (4, "dirigeant + domaine typosquatté", "anac-lab.test", "Marie Durand", NEUTRE, "ok", None,
     "outil de quarantaine (rien chez client@) + alerte [CRITIQUE] chez administrateur@"),
]


def construire(niveau, scenario, domaine, nom, texte, dkim, piece):
    m = EmailMessage()
    m["From"] = f"{nom} <contact@{domaine}>"
    m["To"] = DESTINATAIRE
    m["Subject"] = f"Verif manuelle N{niveau} attendu - {scenario} [{TAG}]"
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    m["Message-ID"] = f"<{TAG}.N{niveau}@{domaine}>"
    m.set_content(texte)
    if piece:
        m.add_attachment(piece[1], maintype="application", subtype="octet-stream", filename=piece[0])
    raw = m.as_bytes().replace(b"\n", b"\r\n")
    if dkim:
        raw = dkim_sign(raw, domaine)
    if dkim == "cassee":
        raw += b"P.S. ligne ajoutee apres la signature.\r\n"
    return raw


def main():
    print(f"Lot {TAG} -> {DESTINATAIRE}\n")
    for niveau, scenario, domaine, nom, texte, dkim, piece, ou in SCENARIOS:
        reponse = send_external(f"contact@{domaine}", [DESTINATAIRE],
                                construire(niveau, scenario, domaine, nom, texte, dkim, piece))
        print(f"N{niveau} attendu  {scenario:<45} SMTP {reponse}\n            -> {ou}")
    print(f"\nObjets des messages : « Verif manuelle N… [{TAG}] » ; traitement en une dizaine de secondes.")


if __name__ == "__main__":
    main()
