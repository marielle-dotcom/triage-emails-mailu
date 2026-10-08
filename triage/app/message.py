"""Lecture du message pour les filtres (lecture seule, le message n'est jamais réécrit).

Le message est analysé une seule fois ; chaque filtre consulte ensuite les
éléments déjà extraits : expéditeur affiché, objet, texte, liens, pièces jointes.
"""

import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass, field
from email import message_from_bytes
from email.policy import default as default_policy
from email.utils import parseaddr
from html.parser import HTMLParser

ZIP_MAX_BYTES = 20_000_000  # au-delà, le contenu de l'archive n'est pas listé
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)


def normaliser(texte):
    """Minuscules, sans accents, espaces réduits : base de comparaison des mots-clés."""
    texte = unicodedata.normalize("NFKD", texte or "")
    texte = "".join(c for c in texte if not unicodedata.combining(c))
    return " ".join(texte.lower().split())


class _LiensHTML(HTMLParser):
    """Collecte le texte visible et les liens <a href> (destination, texte affiché)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.texte, self.liens = [], []
        self._href, self._lien_texte = None, []
        self._ignore = 0  # profondeur dans <style>/<script> : du code, pas du texte visible

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self._ignore += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._lien_texte = []

    def handle_endtag(self, tag):
        if tag in ("style", "script") and self._ignore:
            self._ignore -= 1
        if tag == "a" and self._href is not None:
            self.liens.append((self._href.strip(), " ".join("".join(self._lien_texte).split())))
            self._href = None

    def handle_data(self, data):
        if self._ignore:
            return
        self.texte.append(data)
        if self._href is not None:
            self._lien_texte.append(data)


@dataclass
class Lien:
    url: str
    texte: str = ""  # texte affiché (liens HTML uniquement)


@dataclass
class PieceJointe:
    nom: str
    contenu_archive: list = field(default_factory=list)  # noms des fichiers d'un zip


@dataclass
class Message:
    nom_affiche: str = ""
    adresse: str = ""
    domaine: str = ""
    objet: str = ""
    texte: str = ""  # texte brut + texte du HTML, normalisé
    liens: list = field(default_factory=list)
    pieces_jointes: list = field(default_factory=list)


def _lister_zip(donnees):
    if len(donnees) > ZIP_MAX_BYTES:
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(donnees)) as archive:
            return [info.filename for info in archive.infolist() if not info.is_dir()]
    except (zipfile.BadZipFile, ValueError, OSError):
        return []


def _texte(part):
    """Contenu texte d'une partie ; jeu de caractères inconnu ou invalide → décodage UTF-8 tolérant."""
    try:
        return part.get_content()
    except (LookupError, UnicodeError, ValueError, AssertionError):
        return (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")


def lire_message(raw):
    msg = message_from_bytes(raw, policy=default_policy)
    m = Message()
    nom, adresse = parseaddr(str(msg.get("From", "")))
    m.nom_affiche, m.adresse = nom.strip(), adresse.strip().lower()
    m.domaine = m.adresse.rsplit("@", 1)[-1] if "@" in m.adresse else ""
    m.objet = str(msg.get("Subject", ""))

    morceaux = [m.objet]
    for part in msg.walk():
        if part.is_multipart():
            continue
        nom_fichier = part.get_filename()
        type_mime = part.get_content_type()
        if nom_fichier:
            pj = PieceJointe(nom=nom_fichier)
            if nom_fichier.lower().endswith(".zip") or type_mime in ("application/zip", "application/x-zip-compressed"):
                pj.contenu_archive = _lister_zip(part.get_payload(decode=True) or b"")
            m.pieces_jointes.append(pj)
            continue
        if type_mime == "text/plain":
            texte = _texte(part)
            morceaux.append(texte)
            m.liens.extend(Lien(url=u) for u in URL_RE.findall(texte))
        elif type_mime == "text/html":
            analyseur = _LiensHTML()
            analyseur.feed(_texte(part))
            morceaux.append(" ".join(analyseur.texte))
            m.liens.extend(Lien(url=href, texte=texte) for href, texte in analyseur.liens)
    m.texte = normaliser(" ".join(morceaux))
    return m
