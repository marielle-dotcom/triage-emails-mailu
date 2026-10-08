"""Stockage de quarantaine séparé de la messagerie (étape 5).

Les messages N3 et N4 ne sont plus réinjectés dans Mailu : ils sont écrits tels
quels dans un dossier réservé au filtre et à l'outil de quarantaine, sans accès
IMAP ni webmail. Leur empreinte SHA-256 est enregistrée en base pour prouver
qu'ils n'ont pas été modifiés jusqu'à leur libération ou leur suppression.
"""

import hashlib
import os
from pathlib import Path

DOSSIER = Path(os.environ.get("TRIAGE_QUARANTINE_DIR", "/quarantaine"))


def chemin(triage_id):
    if not triage_id.isalnum():  # identifiant interne : 12 caractères hexadécimaux
        raise ValueError(f"identifiant de quarantaine invalide : {triage_id!r}")
    return DOSSIER / f"{triage_id}.eml"


def stocker(triage_id, contenu):
    """Écrit le message de façon atomique (fichier temporaire, fsync, lien) ; renvoie son SHA-256.

    os.link échoue si le fichier final existe : un message en quarantaine n'est
    jamais écrasé.
    """
    final = chemin(triage_id)
    temporaire = final.with_suffix(".tmp")
    fd = os.open(temporaire, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(contenu)
            f.flush()
            os.fsync(f.fileno())
        os.link(temporaire, final)
    finally:
        temporaire.unlink(missing_ok=True)
    return hashlib.sha256(contenu).hexdigest()
