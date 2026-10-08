"""Filtre « nom affiché incohérent » : le nom affiché ne correspond pas au domaine réel.

Déclenché si le nom affiché :
- contient une adresse ou un domaine différent du domaine d'expédition ;
- cite une organisation protégée alors que le domaine n'est pas l'un des siens ;
- est celui d'un dirigeant alors que le message vient d'un domaine externe.
"""

import re

from domaines import appartient, est_interne
from filtres import Resultat
from message import normaliser

NOM = "display_name_mismatch"
DOMAINE_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}")
# Étape 6 : extensions reconnues pour qu'un mot du nom affiché compte comme un domaine ;
# sans cela, des initiales (« Craig R.Hughes », « D.McMann ») passaient pour des domaines.
EXTENSIONS = {"com", "net", "org", "info", "biz", "io", "co", "me", "app", "dev", "online", "site", "xyz",
              "top", "shop", "cloud", "email", "live", "gov", "edu", "int", "eu", "fr", "be", "ch", "ca",
              "de", "uk", "us", "es", "it", "nl", "pt", "lu", "ma", "sn", "ci", "cm", "dz", "tn", "bj",
              "tg", "bf", "ml", "ne", "ga", "cg", "cd", "mg", "ru", "cn", "jp", "in", "br", "au", "za",
              "lab", "test"}


def domaine_plausible(cite):
    """Vrai si le mot cité ressemble à un vrai domaine (et non à des initiales)."""
    libelles = cite.split(".")
    return len(libelles[-2]) >= 2 and libelles[-1] in EXTENSIONS


def dirigeant_cite(nom_affiche, referentiels):
    """Nom du dirigeant dont tous les mots figurent dans le nom affiché, sinon ""."""
    mots = set(re.findall(r"[a-z]+", normaliser(nom_affiche)))
    for d in referentiels.get("dirigeants", {}).get("dirigeants", []):
        if mots and set(re.findall(r"[a-z]+", normaliser(d["nom"]))) <= mots:
            return d["nom"]
    return ""


def verifier(message, referentiels):
    nom, domaine = normaliser(message.nom_affiche), message.domaine
    if not nom or not domaine:
        return Resultat(NOM, False)
    for cite in DOMAINE_RE.findall(nom):
        if not domaine_plausible(cite):
            continue
        if not appartient(domaine, cite) and not appartient(cite, domaine):
            return Resultat(NOM, True, f"nom affiché « {message.nom_affiche} » mais domaine {domaine}")
    for org in referentiels.get("organisations", {}).get("organisations", []):
        if any(appartient(domaine, d) for d in org.get("domaines", [])):
            continue
        for alias in org.get("alias", []):
            if re.search(r"\b" + re.escape(normaliser(alias)) + r"\b", nom):
                return Resultat(NOM, True, f"nom affiché « {message.nom_affiche} » ({org['nom']}) mais domaine {domaine}")
    dirigeant = dirigeant_cite(message.nom_affiche, referentiels)
    if dirigeant and not est_interne(domaine, referentiels):
        return Resultat(NOM, True, f"nom du dirigeant {dirigeant} depuis le domaine externe {domaine}")
    return Resultat(NOM, False)
