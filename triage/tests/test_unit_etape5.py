"""Tests unitaires de l'étape 5 : stockage de quarantaine et fichier d'attente des décisions.

Usage : triage/tests/.venv/bin/python -m pytest -q triage/tests/test_unit_etape5.py
"""

import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))


@pytest.fixture
def quarantaine(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_QUARANTINE_DIR", str(tmp_path))
    import quarantaine as module
    return importlib.reload(module)


@pytest.fixture
def journal(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_DB_DSN", "")
    monkeypatch.setenv("TRIAGE_SPOOL", str(tmp_path / "attente.jsonl"))
    import journal as module
    return importlib.reload(module)


def test_stockage_atomique_et_empreinte(quarantaine, tmp_path):
    contenu = b"X-Risk-Level: 3\r\nFrom: a@b.test\r\n\r\ncorps\r\n"
    sha = quarantaine.stocker("abc123def456", contenu)
    fichier = tmp_path / "abc123def456.eml"
    assert fichier.read_bytes() == contenu and sha == hashlib.sha256(contenu).hexdigest()
    assert oct(fichier.stat().st_mode & 0o777) == "0o600"
    assert not list(tmp_path.glob("*.tmp"))


def test_stockage_refuse_un_identifiant_dangereux(quarantaine):
    with pytest.raises(ValueError):
        quarantaine.stocker("../../etc/passwd", b"x")


def test_stockage_ne_remplace_jamais_un_message(quarantaine):
    quarantaine.stocker("aaaaaaaaaaaa", b"premier")
    with pytest.raises(FileExistsError):
        quarantaine.stocker("aaaaaaaaaaaa", b"second")


def test_base_absente_decision_mise_en_attente(journal, tmp_path):
    assert journal.enregistrer({"triage_id": "t1", "niveau": 0}) is False
    assert journal.enregistrer({"triage_id": "t2", "niveau": 3}) is False
    lignes = [json.loads(l) for l in (tmp_path / "attente.jsonl").read_text().splitlines()]
    assert [l["triage_id"] for l in lignes] == ["t1", "t2"]


def test_ligne_respecte_l_ordre_des_colonnes(journal):
    valeurs = journal.ligne({"triage_id": "t1", "score": 5, "niveau": 3, "raisons": {"spf": "x"}})
    assert len(valeurs) == len(journal.COLONNES)
    assert valeurs[journal.COLONNES.index("score")] == 5
