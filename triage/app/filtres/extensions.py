"""Filtre « extension suspecte » : pièce jointe exécutable, script, double extension ou nom piégé."""

from filtres import Resultat

NOM = "suspicious_attachment"
RTLO = chr(0x202E)  # caractère invisible d'inversion droite-gauche (U+202E) : « facture[U+202E]fdp.exe » s'affiche « factureexe.pdf »


def _examiner(nom, conf):
    nom_bas = nom.lower().strip().rstrip(".")
    morceaux = nom_bas.rsplit("/", 1)[-1].split(".")
    ext = morceaux[-1] if len(morceaux) > 1 else ""
    if RTLO in nom:
        return f"nom piégé (inversion de sens) : {nom!r}"
    if ext in conf.get("dangereuses", []):
        if len(morceaux) > 2 and morceaux[-2] in conf.get("leurres", []):
            return f"double extension : {nom}"
        return f"extension dangereuse : {nom}"
    return ""


def verifier(message, referentiels):
    conf = referentiels.get("extensions", {})
    raisons = []
    for pj in message.pieces_jointes:
        raison = _examiner(pj.nom, conf)
        if raison:
            raisons.append(raison)
        for membre in pj.contenu_archive:
            raison = _examiner(membre, conf)
            if raison:
                raisons.append(f"{raison} (dans {pj.nom})")
    return Resultat(NOM, bool(raisons), " ; ".join(raisons))
