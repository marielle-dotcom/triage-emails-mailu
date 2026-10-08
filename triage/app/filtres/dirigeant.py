"""Déclencheur direct « usurpation confirmée d'un dirigeant » (§4.1), hors score → N4.

Conditions cumulées : nom affiché d'un dirigeant, domaine externe, et au moins
un indice fort (domaine typosquatté ou récent). Sans indice fort, le cas compte
seulement dans le filtre « nom affiché ».
"""

from domaines import est_interne
from filtres import age_domaine, typosquatting
from filtres.nom_affiche import dirigeant_cite

NOM = "ceo_fraud"
INDICES_FORTS = {typosquatting.NOM, age_domaine.NOM}


def declenche(message, resultats, referentiels):
    if not dirigeant_cite(message.nom_affiche, referentiels):
        return False
    if not message.domaine or est_interne(message.domaine, referentiels):
        return False
    return any(r.declenche and r.nom in INDICES_FORTS for r in resultats)
