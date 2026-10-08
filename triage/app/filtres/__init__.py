"""Filtres calculés par le système de triage (1 point chacun s'il est déclenché).

Chaque filtre est un module exposant NOM et verifier(message, referentiels),
qui renvoie un Resultat. Ajouter un filtre = ajouter un module et l'inscrire
dans FILTRES ci-dessous.
"""

import logging
from dataclasses import dataclass


@dataclass
class Resultat:
    nom: str
    declenche: bool
    raison: str = ""


from filtres import age_domaine, extensions, liens, mots_cles, nom_affiche, typosquatting  # noqa: E402

# Les 6 filtres du document d'architecture (§3.2), dans l'ordre d'exécution.
FILTRES = [typosquatting, age_domaine, mots_cles, liens, extensions, nom_affiche]


def executer(message, referentiels):
    """Exécute les filtres ; un filtre qui plante compte comme non déclenché (journalisé)
    au lieu de faire échouer toute l'analyse (451 répétés, puis rebond vers l'expéditeur)."""
    resultats = []
    for f in FILTRES:
        try:
            resultats.append(f.verifier(message, referentiels))
        except Exception as exc:
            logging.getLogger("triage").exception("filtre %s en erreur", f.NOM)
            resultats.append(Resultat(f.NOM, False, f"erreur interne : {type(exc).__name__}"))
    return resultats
