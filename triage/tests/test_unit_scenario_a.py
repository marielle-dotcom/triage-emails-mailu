"""Tests unitaires du scénario A : hébergeurs gratuits de pages dans le filtre « liens masqués ».

Le contrôle du typosquatting sur les liens, essayé puis retiré (0 % du phishing de
calibrage détecté, faux positifs sur outlook.4team.biz), n'est pas testé ici.

Usage : triage/tests/.venv/bin/python -m pytest -q triage/tests/test_unit_scenario_a.py
"""

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "app"))

from filtres import liens  # noqa: E402
from message import Lien, Message  # noqa: E402
from referentiels import charger  # noqa: E402

REF = charger(RACINE / "referentiels")


def msg(adresse="info@boulangerie-dupont.test", nom="", urls=()):
    return Message(nom_affiche=nom, adresse=adresse, domaine=adresse.rsplit("@", 1)[-1],
                   liens=[Lien(url=u) for u in urls])


# --- Liens masqués : hébergeurs gratuits de pages ------------------------------------------

def test_hebergeur_gratuit_declenche():
    for url in ["https://secure-docs.web.app/verify", "https://xyz.workers.dev/?e=a@b.c",
                "https://mailbox-update.glitch.me/", "https://login.pages.dev/", "https://forms.gle/AbC"]:
        r = liens.verifier(msg(urls=[url]), REF)
        assert r.declenche and "hébergeur gratuit" in r.raison, url


def test_reseaux_de_contenu_et_sites_ordinaires_ne_declenchent_pas():
    for url in ["https://s3.amazonaws.com/img/logo.png", "https://d1.cloudfront.net/a.png",
                "https://storage.googleapis.com/b/c.png", "https://www.legitime.test/compte",
                "https://notpages.dev.example.test/"]:
        assert not liens.verifier(msg(urls=[url]), REF).declenche, url
