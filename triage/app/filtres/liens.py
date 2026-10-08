"""Filtre « liens masqués » : lien raccourci, adresse IP, hébergeur gratuit de pages, ou texte affiché trompeur."""

import ipaddress
import re
from urllib.parse import urlparse

from filtres import Resultat

NOM = "masked_links"
DOMAINE_RE = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def _hote(url):
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:  # URL mal formée (ex. « http://[UnsubscribeURL] ») : ignorée, jamais d'erreur
        return ""


def _meme_domaine(a, b):
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _est_ip(hote):
    try:
        ipaddress.ip_address(hote)
        return True
    except ValueError:
        return False


def verifier(message, referentiels):
    conf = referentiels.get("raccourcisseurs", {})
    raccourcisseurs = set(conf.get("domaines", []))
    passerelles = set(conf.get("ipfs", []))  # étape 6 : passerelles IPFS et redirecteurs
    hebergeurs = set(conf.get("hebergeurs", []))  # scénario A : hébergeurs gratuits de pages
    raisons = []
    for lien in message.liens:
        if lien.url.lower().startswith(("mailto:", "tel:", "#")):
            continue
        hote = _hote(lien.url)
        if not hote:
            continue
        if any(hote == r or hote.endswith("." + r) for r in raccourcisseurs):
            raisons.append(f"lien raccourci : {hote}")
        elif any(hote == r or hote.endswith("." + r) for r in passerelles):
            raisons.append(f"lien via passerelle ou redirecteur : {hote}")
        elif any(hote == r or hote.endswith("." + r) for r in hebergeurs):
            raisons.append(f"lien vers un hébergeur gratuit de pages : {hote}")
        elif _est_ip(hote):
            raisons.append(f"lien vers une adresse IP : {hote}")
        elif lien.texte:
            affiche = DOMAINE_RE.search(lien.texte)
            if affiche and not _meme_domaine(affiche.group(1).lower(), hote):
                raisons.append(f"texte « {affiche.group(1)} » mais destination {hote}")
    return Resultat(NOM, bool(raisons), " ; ".join(dict.fromkeys(raisons)))
