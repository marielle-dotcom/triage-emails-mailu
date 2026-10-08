"""Tests unitaires de l'étape 4 : quarantaine, alerte, en-tête X-Original-Recipient.

Usage : triage/tests/.venv/bin/python -m pytest -q triage/tests/test_unit_etape4.py
"""

import sys
from email import message_from_bytes
from email.policy import default as default_policy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

import actions  # noqa: E402
from headers import strip_headers  # noqa: E402
from score import Decision  # noqa: E402

FIELDS = {"triage_id": "abc123", "message_id": "<x@arnaque.test>",
          "header_from": "Légitime Services <a@legitime-support.test>", "rcpt_to": ["client@anac.lab"],
          "filters": {"masked_links": "lien raccourci : bit.ly", "typosquatting": "http://legitime-support.test"}}


def test_niveaux_0_a_2_livres_au_destinataire():
    for niveau, libelle in ((0, "livre"), (1, "livre"), (2, "suspect")):
        assert actions.libelle_action(Decision(0, niveau)) == libelle
        assert actions.entetes_action(Decision(0, niveau), ["client@anac.lab"]) == {}


def test_niveaux_3_et_4_en_quarantaine():
    for niveau in (3, 4):
        assert actions.en_quarantaine(Decision(5, niveau))
        assert actions.libelle_action(Decision(5, niveau)) == "quarantaine"
        assert actions.entetes_action(Decision(5, niveau), ["client@anac.lab"]) == {"X-Original-Recipient": "client@anac.lab"}


def test_x_original_recipient_forge_supprime():
    raw = b"X-Original-Recipient: pirate@evil.test\r\nFrom: a@b.test\r\n\r\ncorps\r\n"
    out, retires = strip_headers(raw)
    assert retires == ["x-original-recipient"] and b"pirate" not in out


def test_alerte_metadonnees_desamorcees():
    m = message_from_bytes(actions.alerte(Decision(5, 3, ["spf", "masked_links"]), FIELDS), policy=default_policy)
    assert m["To"] == "securite@anac.lab"
    assert m["Subject"].startswith("[Triage N3]") and "abc123" in m["Subject"]
    corps = m.get_content()
    assert "bit[.]ly" in corps and "client[@]anac[.]lab" in corps
    assert "http" not in corps and "bit.ly" not in corps and "@legitime-support.test" not in corps


def test_alerte_n4_critique():
    m = message_from_bytes(actions.alerte(Decision(2, 4, ["ceo_fraud"], "ceo_fraud"), FIELDS), policy=default_policy)
    assert m["Subject"].startswith("[CRITIQUE] [Triage N4]")
    assert "déclencheur direct : ceo_fraud" in m.get_content()
