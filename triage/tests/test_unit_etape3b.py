"""Tests unitaires de l'étape 3b : typosquatting, âge du domaine, nom affiché, dirigeant.

Usage : triage/tests/.venv/bin/python -m pytest -q triage/tests/test_unit_etape3b.py
"""

import datetime
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "app"))

import filtres  # noqa: E402
from filtres import age_domaine, dirigeant, nom_affiche, typosquatting  # noqa: E402
from message import Message  # noqa: E402
from referentiels import charger  # noqa: E402

REF = charger(RACINE / "referentiels")


def msg(adresse, nom=""):
    return Message(nom_affiche=nom, adresse=adresse, domaine=adresse.rsplit("@", 1)[-1])


# --- Typosquatting ----------------------------------------------------------------------

def test_typosquatting_detecte_les_sosies():
    for domaine in ["1egitime.test", "legitlme.test", "xn--lgitime-dya.test", "legitime-support.test",
                    "anac-lab.test", "anac.com", "paypa1.com", "rnicrosoft.com", "banque-partenaires.test"]:
        assert typosquatting.verifier(msg(f"x@{domaine}"), REF).declenche, domaine


def test_typosquatting_ignore_les_vrais_domaines_et_les_inconnus():
    for domaine in ["legitime.test", "anac.lab", "mail.anac.lab", "paypal.com", "usurpe.test",
                    "nouveau-service.test", "tout-faux.test", "gmail.com"]:
        assert not typosquatting.verifier(msg(f"x@{domaine}"), REF).declenche, domaine


# --- Âge du domaine -----------------------------------------------------------------------

def test_age_domaine_recent_ancien_inconnu():
    assert age_domaine.verifier(msg("x@nouveau-service.test"), REF).declenche      # 5 jours
    assert not age_domaine.verifier(msg("x@legitime.test"), REF).declenche         # 2015
    r = age_domaine.verifier(msg("x@jamais-vu.test"), REF)
    assert not r.declenche and r.raison == "âge inconnu"


def test_age_domaine_date_et_sous_domaine():
    ref = {"ages_domaines": {"seuil_jours": 30, "domaines": {"exemple.test": datetime.date(2026, 9, 20)}}}
    assert age_domaine.age_en_jours("mail.exemple.test", ref, datetime.date(2026, 10, 1)) == 11


# --- Nom affiché ---------------------------------------------------------------------------

def test_nom_affiche_organisation_citee_depuis_un_autre_domaine():
    assert nom_affiche.verifier(msg("x@1egitime.test", "Légitime Services"), REF).declenche
    assert nom_affiche.verifier(msg("x@arnaque.test", "Service PayPal"), REF).declenche


def test_nom_affiche_adresse_citee_differente():
    assert nom_affiche.verifier(msg("x@arnaque.test", "support@banque-partenaire.test"), REF).declenche


def test_nom_affiche_coherent():
    assert not nom_affiche.verifier(msg("contact@legitime.test", "Légitime Services"), REF).declenche
    assert not nom_affiche.verifier(msg("x@usurpe.test", "Service"), REF).declenche
    assert not nom_affiche.verifier(msg("marie.durand@anac.lab", "Marie Durand"), REF).declenche


def test_nom_affiche_dirigeant_externe_compte():
    r = nom_affiche.verifier(msg("marie.durand@gmail.com", "Marie DURAND"), REF)
    assert r.declenche and "Marie Durand" in r.raison


# --- Déclencheur direct « dirigeant » ------------------------------------------------------

def resultats(m):
    return filtres.executer(m, REF)


def test_dirigeant_avec_domaine_typosquatte_declenche_n4():
    m = msg("m.durand@anac-lab.test", "Marie Durand")
    assert dirigeant.declenche(m, resultats(m), REF)


def test_dirigeant_depuis_messagerie_personnelle_ne_declenche_pas():
    # Nom + domaine externe sans indice fort : pas de N4, seul le filtre « nom affiché » compte.
    m = msg("marie.durand@gmail.com", "Marie Durand")
    r = resultats(m)
    assert not dirigeant.declenche(m, r, REF)
    assert [x.nom for x in r if x.declenche] == ["display_name_mismatch"]


def test_dirigeant_interne_ne_declenche_pas():
    m = msg("marie.durand@anac.lab", "Marie Durand")
    assert not dirigeant.declenche(m, resultats(m), REF)


def test_six_filtres_dans_l_ordre():
    assert [r.nom for r in resultats(msg("x@legitime.test"))] == [
        "typosquatting", "recent_domain", "urgency_keywords", "masked_links",
        "suspicious_attachment", "display_name_mismatch"]


def test_nom_affiche_initiales_ne_sont_pas_un_domaine():
    # Défaut trouvé sur le corpus (étape 6) : « R.Hughes » était lu comme un domaine.
    for nom in ("Craig R.Hughes", "D.McMann", "C.Lee Taylor", "Nalin nal.sav Savara"):
        assert not nom_affiche.verifier(msg("craig@deersoft.com", nom), REF).declenche, nom
    assert nom_affiche.verifier(msg("x@arnaque.test", "service@paypal.com"), REF).declenche
