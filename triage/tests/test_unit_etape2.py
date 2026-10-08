"""Tests unitaires de l'étape 2 : en-têtes forgés et lecture des verdicts natifs.

Usage : triage/tests/.venv/bin/python -m pytest -q triage/tests/test_unit_etape2.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from headers import strip_headers  # noqa: E402
from verdicts import read_native_verdicts  # noqa: E402

BODY = b"\r\nCorps \xc3\xa9 intact\r\nX-Risk-Level: 0 (dans le corps, ne pas toucher)\r\n"


def msg(*headers):
    return b"".join(h.encode() + b"\r\n" for h in headers) + BODY


# --- Suppression des en-têtes forgés -------------------------------------------------

def test_forged_triage_headers_removed_body_untouched():
    raw = msg("From: a@b.test", "X-Risk-Level: 0", "x-phishing-score: 0",
              "X-Detection-Type: aucun", "X-Warning-Banner: false", "Subject: s")
    out, removed = strip_headers(raw)
    assert removed == ["x-risk-level", "x-phishing-score", "x-detection-type", "x-warning-banner"]
    assert out == msg("From: a@b.test", "Subject: s")
    assert out.endswith(BODY)


def test_folded_forged_header_removed_entirely():
    raw = msg("From: a@b.test", "X-Detection-Type: ligne1", "\tligne2", "Subject: s")
    out, _ = strip_headers(raw)
    assert out == msg("From: a@b.test", "Subject: s")


def test_message_without_triage_headers_returned_identical():
    raw = msg("From: a@b.test", "Subject: s")
    out, removed = strip_headers(raw)
    assert out is raw and removed == []


# --- Lecture des verdicts --------------------------------------------------------------

def test_all_pass():
    v = read_native_verdicts(msg(
        "Authentication-Results: mail.anac.lab;",
        "\tdkim=pass header.d=legitime.test header.s=lab;",
        "\tspf=pass smtp.mailfrom=contact@legitime.test;",
        "\tdmarc=pass (policy=reject) header.from=legitime.test",
        "From: a@legitime.test"))
    assert (v.spf, v.dkim, v.dmarc, v.auth_points) == ("pass", "pass", "pass", 0)


def test_spf_and_dmarc_fail():
    v = read_native_verdicts(msg(
        "Authentication-Results: mail.anac.lab; dkim=none; spf=fail smtp.mailfrom=x@usurpe.test;"
        " dmarc=fail reason=\"No valid SPF, No valid DKIM\" header.from=usurpe.test (policy=none)"))
    assert (v.spf, v.dkim, v.dmarc) == ("fail", "none", "fail")
    assert v.points == {"spf": 1, "dkim": 0, "dmarc": 1}


def test_softfail_does_not_count_by_default():
    v = read_native_verdicts(msg("Authentication-Results: mail.anac.lab; spf=softfail; dmarc=fail"))
    assert v.points == {"spf": 0, "dkim": 0, "dmarc": 1}


def test_none_result():
    v = read_native_verdicts(msg("Authentication-Results: mail.anac.lab;", "\tnone"))
    assert v.authres_found and (v.spf, v.dkim, v.dmarc, v.auth_points) == ("absent", "absent", "absent", 0)


def test_only_first_trusted_authres_is_read():
    # Le premier (le plus haut) est celui de Rspamd ; le second, plus bas, est forgé.
    v = read_native_verdicts(msg(
        "Authentication-Results: mail.anac.lab; spf=fail; dmarc=fail",
        "Authentication-Results: mail.anac.lab; spf=pass; dkim=pass; dmarc=pass"))
    assert (v.spf, v.dmarc) == ("fail", "fail")


def test_foreign_authserv_id_ignored():
    v = read_native_verdicts(msg("Authentication-Results: mx.attaquant.test; spf=pass; dkim=pass; dmarc=pass"))
    assert not v.authres_found and v.spf == "absent"


def test_two_dkim_signatures_pass_wins():
    v = read_native_verdicts(msg("Authentication-Results: mail.anac.lab; dkim=fail; dkim=pass; spf=pass"))
    assert v.dkim == "pass" and v.points["dkim"] == 0


def test_dkim_fail_counts():
    v = read_native_verdicts(msg("Authentication-Results: mail.anac.lab; dkim=fail (body hash mismatch); spf=pass"))
    assert v.points == {"spf": 0, "dkim": 1, "dmarc": 0}


def test_virus_and_spam_bar():
    v = read_native_verdicts(msg("X-Virus: CLAM_VIRUS(Eicar-Signature)", "X-Spamd-Bar: ++++"))
    assert v.virus and "CLAM_VIRUS" in v.virus_detail and v.spam_bar == "++++"
