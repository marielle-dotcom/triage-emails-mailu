"""Filtre « mots-clés d'urgence » : formulations typiques du phishing dans l'objet ou le texte."""

import re

from filtres import Resultat
from message import normaliser

NOM = "urgency_keywords"


def verifier(message, referentiels):
    conf = referentiels.get("mots_cles", {})
    seuil = int(conf.get("seuil", 2))
    trouves = []
    for expression in conf.get("expressions", []):
        motif = r"\b" + re.escape(normaliser(expression)) + r"\b"
        if re.search(motif, message.texte):
            trouves.append(expression)
    return Resultat(NOM, len(trouves) >= seuil,
                    f"{len(trouves)} expression(s) (seuil {seuil}) : {', '.join(trouves)}" if trouves else "")
