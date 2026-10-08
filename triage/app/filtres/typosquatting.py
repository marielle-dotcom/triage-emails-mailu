"""Filtre « typosquatting » : domaine d'expédition visuellement proche d'un domaine protégé."""

from domaines import appartient, distance, domaines_proteges, libelle, squelette, unicode_domaine
from filtres import Resultat

NOM = "typosquatting"


def imitation(domaine, protege):
    """Raison pour laquelle `domaine` imite `protege`, ou "" s'il ne l'imite pas."""
    if not domaine or appartient(domaine, protege):
        return ""
    if squelette(domaine) == squelette(protege):
        return f"caractères sosies de {protege}"
    tolerance = 1 if len(protege) <= 8 else 2
    if distance(unicode_domaine(domaine), protege) <= tolerance:
        return f"à {distance(unicode_domaine(domaine), protege)} caractère(s) de {protege}"
    nom = libelle(protege)
    if libelle(domaine) == nom:
        return f"même nom que {protege}, autre extension"
    if len(nom) >= 4 and squelette(nom) in libelle(squelette(domaine)).split("-"):
        return f"nom de {protege} accolé à un autre mot"
    return ""


def verifier(message, referentiels):
    proteges = domaines_proteges(referentiels)
    # Un domaine protégé n'imite pas les autres domaines de la liste (paypal.com / paypal.fr).
    if any(appartient(message.domaine, p) for p in proteges):
        return Resultat(NOM, False)
    for protege in proteges:
        raison = imitation(message.domaine, protege)
        if raison:
            return Resultat(NOM, True, f"{message.domaine} : {raison}")
    return Resultat(NOM, False)
