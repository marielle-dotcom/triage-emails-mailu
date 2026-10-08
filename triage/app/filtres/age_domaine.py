"""Filtre « âge du domaine » : domaine d'expédition créé il y a moins de `seuil_jours`.

Le lab n'a pas accès au WHOIS : les âges viennent de referentiels/ages_domaines.yaml.
Un domaine absent du fichier a un âge inconnu et ne déclenche pas le filtre.
"""

import datetime

from domaines import appartient
from filtres import Resultat

NOM = "recent_domain"


def age_en_jours(domaine, referentiels, aujourd_hui=None):
    conf = referentiels.get("ages_domaines", {})
    aujourd_hui = aujourd_hui or datetime.date.today()
    # Le domaine exact d'abord, puis ses parents (mail.exemple.test → exemple.test).
    for connu, valeur in sorted(conf.get("domaines", {}).items(), key=lambda kv: -len(kv[0])):
        if appartient(domaine, connu):
            if isinstance(valeur, int):
                return valeur
            if isinstance(valeur, str):
                valeur = datetime.date.fromisoformat(valeur)
            return (aujourd_hui - valeur).days
    return None


def verifier(message, referentiels):
    seuil = int(referentiels.get("ages_domaines", {}).get("seuil_jours", 30))
    age = age_en_jours(message.domaine, referentiels)
    if age is None:
        return Resultat(NOM, False, "âge inconnu")
    return Resultat(NOM, age < seuil, f"{message.domaine} créé il y a {age} jour(s) (seuil {seuil})")
