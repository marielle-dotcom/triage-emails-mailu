"""Tests unitaires de l'étape 3a : lecture du message, 3 filtres, score, en-têtes.

Usage : triage/tests/.venv/bin/python -m pytest -q triage/tests/test_unit_etape3a.py
"""

import io
import sys
import zipfile
from email.message import EmailMessage
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "app"))

import filtres  # noqa: E402
from filtres import extensions, liens, mots_cles  # noqa: E402
from headers import ajouter_entetes  # noqa: E402
from message import lire_message  # noqa: E402
from referentiels import charger  # noqa: E402
from score import decider, niveau_pour  # noqa: E402
from verdicts import NativeVerdicts  # noqa: E402

REF = charger(RACINE / "referentiels")


def mail(texte="Bonjour.", html=None, objet="Objet", pieces=()):
    m = EmailMessage()
    m["From"] = "Service <contact@exemple.test>"
    m["To"] = "client@anac.lab"
    m["Subject"] = objet
    m.set_content(texte)
    if html:
        m.add_alternative(html, subtype="html")
    for nom, donnees in pieces:
        m.add_attachment(donnees, maintype="application", subtype="octet-stream", filename=nom)
    return m.as_bytes().replace(b"\n", b"\r\n")


def zip_avec(*noms):
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w") as z:
        for nom in noms:
            z.writestr(nom, b"x")
    return tampon.getvalue()


# --- Lecture du message -------------------------------------------------------------------

def test_lecture_expediteur_et_texte_normalise():
    m = lire_message(mail(texte="Votre COMPTE est Suspendu."))
    assert (m.nom_affiche, m.adresse, m.domaine) == ("Service", "contact@exemple.test", "exemple.test")
    assert "compte est suspendu" in m.texte


# --- Mots-clés d'urgence ---------------------------------------------------------------

def test_mots_cles_deux_expressions_declenchent():
    r = mots_cles.verifier(lire_message(mail(objet="URGENT", texte="Effectuez le virement aujourd'hui.")), REF)
    assert r.declenche and "virement" in r.raison


def test_mots_cles_une_seule_expression_ne_declenche_pas():
    r = mots_cles.verifier(lire_message(mail(texte="Le virement de votre salaire est parti.")), REF)
    assert not r.declenche


def test_mots_cles_accents_et_html():
    r = mots_cles.verifier(lire_message(mail(html="<p>Compte <b>BLOQUÉ</b> : action immédiate requise</p>")), REF)
    assert r.declenche


def test_mots_cles_pas_de_faux_positif_dans_un_mot():
    # « rib » ou « urgent » à l'intérieur d'un autre mot ne comptent pas
    r = mots_cles.verifier(lire_message(mail(texte="Insurgents et contributions.")), REF)
    assert not r.declenche


# --- Liens masqués -------------------------------------------------------------------------

def test_lien_raccourci():
    r = liens.verifier(lire_message(mail(texte="Voir https://bit.ly/3abc")), REF)
    assert r.declenche and "bit.ly" in r.raison


def test_lien_texte_trompeur():
    html = '<a href="http://connexion-securisee.test/login">https://www.banque-partenaire.test</a>'
    r = liens.verifier(lire_message(mail(html=html)), REF)
    assert r.declenche and "connexion-securisee.test" in r.raison


def test_lien_adresse_ip():
    r = liens.verifier(lire_message(mail(html='<a href="http://10.1.2.3/paie">Portail RH</a>')), REF)
    assert r.declenche


def test_lien_coherent_ne_declenche_pas():
    html = ('<a href="https://www.legitime.test/compte">www.legitime.test</a> '
            '<a href="https://legitime.test/aide">Aide</a> <a href="mailto:a@b.test">écrire</a>')
    r = liens.verifier(lire_message(mail(html=html)), REF)
    assert not r.declenche


# --- Extensions suspectes ----------------------------------------------------------------

def test_double_extension():
    r = extensions.verifier(lire_message(mail(pieces=[("facture.pdf.html", b"<html>")])), REF)
    assert r.declenche and "double extension" in r.raison


def test_executable_dans_un_zip():
    r = extensions.verifier(lire_message(mail(pieces=[("documents.zip", zip_avec("lisez-moi.txt", "scan.js"))])), REF)
    assert r.declenche and "scan.js" in r.raison


def test_nom_avec_inversion_de_sens():
    r = extensions.verifier(lire_message(mail(pieces=[("facture‮fdp.exe", b"x")])), REF)
    assert r.declenche


def test_piece_jointe_ordinaire():
    r = extensions.verifier(lire_message(mail(pieces=[("rapport.pdf", b"%PDF"), ("photos.zip", zip_avec("a.jpg"))])), REF)
    assert not r.declenche


# --- Score, niveaux, en-têtes ------------------------------------------------------------

def test_grille():
    assert [niveau_pour(s) for s in range(10)] == [0, 1, 1, 2, 2, 3, 3, 4, 4, 4]


def test_decision_combine_natifs_et_filtres():
    natifs = NativeVerdicts(points={"spf": 1, "dkim": 0, "dmarc": 1})
    resultats = [filtres.Resultat("urgency_keywords", True), filtres.Resultat("masked_links", False)]
    d = decider(natifs, resultats)
    assert (d.score, d.niveau, d.detections, d.bandeau) == (3, 2, ["spf", "dmarc", "urgency_keywords"], False)


def test_declencheur_direct_impose_n4():
    d = decider(NativeVerdicts(points={"spf": 0, "dkim": 0, "dmarc": 0}), [], declencheurs=["virus"])
    assert (d.niveau, d.score, d.entetes()["X-Detection-Type"]) == (4, 0, "virus")


def test_bandeau_n1_et_entetes():
    d = decider(NativeVerdicts(points={"spf": 1, "dkim": 0, "dmarc": 0}), [])
    assert d.entetes() == {"X-Risk-Level": "1", "X-Phishing-Score": "1",
                           "X-Detection-Type": "spf", "X-Warning-Banner": "true"}


def test_entetes_ajoutes_en_tete_message_intact():
    raw = mail()
    out = ajouter_entetes(raw, {"X-Risk-Level": "0", "X-Phishing-Score": "0"})
    assert out == b"X-Risk-Level: 0\r\nX-Phishing-Score: 0\r\n" + raw


def test_executer_tous_les_filtres():
    noms = [r.nom for r in filtres.executer(lire_message(mail()), REF)]
    assert noms == ["typosquatting", "recent_domain", "urgency_keywords", "masked_links",
                    "suspicious_attachment", "display_name_mismatch"]


# --- Robustesse (étape 6 : défauts trouvés sur les corpus publics) -------------------------

def test_url_mal_formee_ne_fait_pas_planter():
    r = liens.verifier(lire_message(mail(html='<a href="http://[UnsubscribeURL]">x</a> <a href="http://[::1">y</a>')), REF)
    assert not r.declenche


def test_jeu_de_caracteres_inconnu_ne_fait_pas_planter():
    raw = (b"From: a@b.test\r\nSubject: s\r\nContent-Type: text/plain; charset=\"UTF-8X-Priority: 3\"\r\n\r\n"
           b"Compte suspendu, virement urgent\r\n")
    assert "compte suspendu" in lire_message(raw).texte


def test_un_filtre_qui_plante_ne_bloque_pas_l_analyse(monkeypatch):
    def plante(message, referentiels):
        raise RuntimeError("panne simulée")
    monkeypatch.setattr(mots_cles, "verifier", plante)
    r = {x.nom: x for x in filtres.executer(lire_message(mail()), REF)}
    assert len(r) == 6 and not r["urgency_keywords"].declenche and "erreur" in r["urgency_keywords"].raison


def test_css_et_scripts_exclus_du_texte():
    html = "<style>.x{max-width:600px;display:none!important}</style><script>var urgent=1;</script><p>Bonjour</p>"
    texte = lire_message(mail(texte="", html=html)).texte
    assert "max-width" not in texte and "var urgent" not in texte and "bonjour" in texte


def test_lien_passerelle_ipfs():
    r = liens.verifier(lire_message(mail(html='<a href="https://cloudflare-ipfs.com/ipfs/bafy/x.html">Voir</a>')), REF)
    assert r.declenche and "passerelle" in r.raison
