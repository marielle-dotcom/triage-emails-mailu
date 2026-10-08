"""Chargement des listes de référence (fichiers YAML de triage/referentiels/)."""

import os
from pathlib import Path

import yaml

DOSSIER = Path(os.environ.get("TRIAGE_REFERENTIELS", Path(__file__).resolve().parent / "referentiels"))


def charger(dossier=DOSSIER):
    """Renvoie {nom du fichier sans extension: contenu}. Lu au démarrage du filtre."""
    return {f.stem: yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            for f in sorted(Path(dossier).glob("*.yaml"))}
