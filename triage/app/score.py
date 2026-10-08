"""Moteur de décision : score binaire sur 9 et grille N0 à N4 (document d'architecture, §4).

Score = 3 verdicts natifs (SPF, DKIM, DMARC) + 6 filtres Python, 1 point chacun.
Un déclencheur direct (virus, usurpation confirmée d'un dirigeant) impose N4
quel que soit le score.
"""

from dataclasses import dataclass, field

# (score minimal, niveau) du plus haut au plus bas
GRILLE = [(7, 4), (5, 3), (3, 2), (1, 1), (0, 0)]
LIBELLES = {0: "Sain", 1: "Faible", 2: "Moyen", 3: "Élevé", 4: "Critique"}
NIVEAUX_BANDEAU = {1}  # choix validé : bandeau « Prudence » pour N1 uniquement


def niveau_pour(score):
    return next(niveau for minimum, niveau in GRILLE if score >= minimum)


@dataclass
class Decision:
    score: int
    niveau: int
    detections: list = field(default_factory=list)  # filtres déclenchés ou déclencheur direct
    declencheur_direct: str = ""

    @property
    def bandeau(self):
        return self.niveau in NIVEAUX_BANDEAU

    def entetes(self):
        return {
            "X-Risk-Level": str(self.niveau),
            "X-Phishing-Score": str(self.score),
            "X-Detection-Type": ",".join(self.detections) or "none",
            "X-Warning-Banner": "true" if self.bandeau else "false",
        }


def decider(natifs, resultats, declencheurs=()):
    """natifs : NativeVerdicts (étape 2) ; resultats : liste de Resultat ; declencheurs : noms."""
    detections = [nom for nom, point in natifs.points.items() if point]
    detections += [r.nom for r in resultats if r.declenche]
    score = len(detections)
    if declencheurs:
        return Decision(score=score, niveau=4, detections=list(declencheurs) + detections,
                        declencheur_direct=",".join(declencheurs))
    return Decision(score=score, niveau=niveau_pour(score), detections=detections)
