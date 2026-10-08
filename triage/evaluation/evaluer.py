"""Banc A de l'étape 6 : évaluation hors ligne du moteur de triage sur des corpus publics.

Chaque message passe dans le même code que le filtre en production (suppression
des en-têtes forgés, lecture du message, 6 filtres, déclencheur « dirigeant »,
grille), sans SMTP ni base. Les verdicts SPF/DKIM/DMARC sont neutralisés
(0 point) : rejouer d'anciens mails depuis le lab les ferait échouer à tort.

Jeux : légitimes = SpamAssassin easy_ham, easy_ham_2, hard_ham (moitié calibrage,
moitié test, répartition fixe par empreinte du fichier) ; phishing = Nazario
2023-2024 (calibrage) et 2025 (test, postérieur : mesure honnête).

Options (variables d'environnement) :
- EVAL_APP=<dossier>       code du filtre évalué (défaut : triage/app ; « avant » = code de l'étape 5)
- EVAL_NATIFS=origine      utilise les verdicts SPF/DKIM/DMARC d'origine du corpus (premier
                           en-tête Authentication-Results, posé par le serveur qui a reçu le
                           phishing) au lieu de les neutraliser ; les légitimes de 2002 n'en
                           ont pas (0 point)
- EVAL_TRANSPOSITION=0     désactive la transposition : le corpus Nazario a été collecté sur
                           l'organisation monkey.org ; par défaut elle est déclarée organisation
                           interne, comme anac.lab en production (mêmes intitulés d'équipe
                           informatique que l'organisation ANAC)

Usage : triage/tests/.venv/bin/python triage/evaluation/evaluer.py <étiquette> [dossier des référentiels]
        → triage/evaluation/resultats/<étiquette>.jsonl et <étiquette>.json (synthèse)
"""

import copy
import hashlib
import inspect
import json
import os
import mailbox
import math
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

ICI = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("EVAL_APP", str(ICI.parent / "app")))
NATIFS_ORIGINE = os.environ.get("EVAL_NATIFS") == "origine"
TRANSPOSITION = os.environ.get("EVAL_TRANSPOSITION", "1") != "0"

import filtres  # noqa: E402
from filtres import dirigeant  # noqa: E402
from headers import strip_headers  # noqa: E402
from message import lire_message  # noqa: E402
from referentiels import charger  # noqa: E402
from score import decider, niveau_pour  # noqa: E402
import verdicts  # noqa: E402
from verdicts import NativeVerdicts  # noqa: E402

if NATIFS_ORIGINE:
    # Le premier Authentication-Results est celui du serveur qui a reçu le message à l'origine.
    verdicts._first_trusted_authres = lambda msg: next(
        (" ".join(str(v).split()) for v in msg.get_all("Authentication-Results", [])), None)

CORPUS = ICI / "corpus"
RESULTATS = ICI / "resultats"
NOMS_FILTRES = ["typosquatting", "recent_domain", "urgency_keywords", "masked_links",
                "suspicious_attachment", "display_name_mismatch"]

# Grilles comparées sur le score produit par le code évalué : (nom, seuil N1, N2, N3, N4).
# Score binaire (en production) : grille du document d'architecture 1/3/5/7 ;
# score pondéré (bareme.yaml, retiré le 2026-10-02, annexe G) : grille 1/3/6/9 et variantes.
GRILLES = [("1/3/5/7", 1, 3, 5, 7), ("1/2/4/6", 1, 2, 4, 6),
           ("1/3/6/9", 1, 3, 6, 9), ("1/4/7/10", 1, 4, 7, 10)]


def messages():
    """(classe, jeu, identifiant, octets) pour chaque message des corpus."""
    for dossier in ("easy_ham", "easy_ham_2", "hard_ham"):
        for f in sorted((CORPUS / dossier).iterdir()):
            if f.name == "cmds":
                continue
            raw = f.read_bytes()
            if raw.startswith(b"From "):  # ligne de séparateur mbox en tête des fichiers SpamAssassin
                raw = raw.split(b"\n", 1)[1]
            jeu = "calibrage" if hashlib.sha256(f.name.encode()).digest()[0] % 2 == 0 else "test"
            yield "legitime", jeu, f"{dossier}/{f.name}", raw
    for annee, jeu in (("2023", "calibrage"), ("2024", "calibrage"), ("2025", "test")):
        boite = mailbox.mbox(str(CORPUS / f"phishing-{annee}.mbox"), create=False)
        for cle in boite.iterkeys():
            yield "phishing", jeu, f"phishing-{annee}/{cle}", boite.get_bytes(cle)


def transposer(ref):
    """Déclare monkey.org (organisation visée par le corpus Nazario) comme organisation interne."""
    ref = copy.deepcopy(ref)
    orgs = ref.setdefault("organisations", {})
    orgs.setdefault("domaines_internes", []).append("monkey.org")
    anac = next((o for o in orgs.get("organisations", []) if o.get("nom") == "ANAC"), {"alias": []})
    orgs.setdefault("organisations", []).append({
        "nom": "monkey.org (organisation du corpus)",
        "alias": ["monkey.org", "monkey"] + [a for a in anac.get("alias", []) if a != "anac"],
        "domaines": ["monkey.org"]})
    return ref


def evaluer_message(raw, ref):
    contenu, _ = strip_headers(raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    natifs = verdicts.read_native_verdicts(contenu) if NATIFS_ORIGINE else \
        NativeVerdicts(points={"spf": 0, "dkim": 0, "dmarc": 0})
    message = lire_message(contenu)
    resultats = filtres.executer(message, ref)
    declencheurs = [dirigeant.NOM] if dirigeant.declenche(message, resultats, ref) else []
    # Seul le code pondéré (backup-avant-retour-binaire) accepte ce paramètre ; le code binaire ne l'a pas.
    options = {"bareme": ref.get("bareme")} if "bareme" in inspect.signature(decider).parameters else {}
    d = decider(natifs, resultats, declencheurs, **options)
    return d.niveau, d.score, d.detections, {r.nom: r.raison for r in resultats if r.declenche}


def part(n, total):
    return round(100 * n / total, 2) if total else 0.0


def synthese(lignes):
    s = {}
    for jeu in ("calibrage", "test"):
        for classe in ("legitime", "phishing"):
            sel = [l for l in lignes if l["jeu"] == jeu and l["classe"] == classe and "erreur" not in l]
            n = len(sel)
            niveaux = Counter(l["niveau"] for l in sel)
            s[f"{jeu}/{classe}"] = {
                "messages": n,
                "erreurs": sum(1 for l in lignes if l["jeu"] == jeu and l["classe"] == classe and "erreur" in l),
                "niveaux_pct": {f"N{i}": part(niveaux[i], n) for i in range(5)},
                "n2_et_plus_pct": part(sum(1 for l in sel if l["niveau"] >= 2), n),
                "n3_et_plus_pct": part(sum(1 for l in sel if l["niveau"] >= 3), n),
                "filtres_pct": {f: part(sum(1 for l in sel if f in l["detections"]), n) for f in NOMS_FILTRES + ["ceo_fraud"]},
            }
    temps = [l["ms"] for l in lignes if "ms" in l]
    s["temps_ms"] = {"mediane": round(statistics.median(temps), 2), "p95": round(sorted(temps)[int(0.95 * len(temps))], 2),
                     "max": round(max(temps), 2), "messages": len(temps)}
    s["grilles"] = grilles(lignes)
    s["poids_proposes"] = poids(lignes)
    return s


def grilles(lignes):
    """Effet de grilles alternatives (score des seuls filtres Python) sur le jeu de test."""
    res = []
    for nom, s1, s2, s3, s4 in GRILLES:
        def niv(sc):
            return 4 if sc >= s4 else 3 if sc >= s3 else 2 if sc >= s2 else 1 if sc >= s1 else 0
        ligne = {"grille": nom}
        for classe in ("legitime", "phishing"):
            sel = [l for l in lignes if l["jeu"] == "test" and l["classe"] == classe and "erreur" not in l]
            ns = [4 if "ceo_fraud" in l["detections"] else niv(l["score"]) for l in sel]
            ligne[f"{classe}_n2_plus_pct"] = part(sum(1 for x in ns if x >= 2), len(ns))
            ligne[f"{classe}_n3_plus_pct"] = part(sum(1 for x in ns if x >= 3), len(ns))
        res.append(ligne)
    return res


def poids(lignes):
    """Poids par filtre (log du rapport de vraisemblance, lissage de Laplace) appris sur le calibrage."""
    cal = [l for l in lignes if l["jeu"] == "calibrage" and "erreur" not in l]
    ph = [l for l in cal if l["classe"] == "phishing"]
    le = [l for l in cal if l["classe"] == "legitime"]
    res = {}
    for f in NOMS_FILTRES:
        p = (sum(1 for l in ph if f in l["detections"]) + 1) / (len(ph) + 2)
        q = (sum(1 for l in le if f in l["detections"]) + 1) / (len(le) + 2)
        res[f] = round(math.log(p / q), 2)
    return res


def main():
    etiquette = sys.argv[1]
    ref = charger(Path(sys.argv[2]) if len(sys.argv) > 2 else ICI.parent / "referentiels")
    if TRANSPOSITION:
        ref = transposer(ref)
    RESULTATS.mkdir(exist_ok=True)
    lignes = []
    debut = time.time()
    with open(RESULTATS / f"{etiquette}.jsonl", "w", encoding="utf-8") as sortie:
        for classe, jeu, ident, raw in messages():
            ligne = {"classe": classe, "jeu": jeu, "id": ident}
            t0 = time.perf_counter()
            try:
                niveau, score, detections, raisons = evaluer_message(raw, ref)
                ligne.update(niveau=niveau, score=score, detections=detections, raisons=raisons)
            except Exception as exc:  # un plantage ici = un 451 en production
                ligne["erreur"] = f"{type(exc).__name__}: {exc}"[:300]
            ligne["ms"] = round((time.perf_counter() - t0) * 1000, 3)
            lignes.append(ligne)
            sortie.write(json.dumps(ligne, ensure_ascii=False) + "\n")
    s = synthese(lignes)
    s["duree_totale_s"] = round(time.time() - debut, 1)
    s["options"] = {"app": os.environ.get("EVAL_APP", "triage/app"), "natifs": "origine" if NATIFS_ORIGINE else "neutres",
                    "transposition": TRANSPOSITION}
    (RESULTATS / f"{etiquette}.json").write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")
    for cle in ("calibrage/legitime", "calibrage/phishing", "test/legitime", "test/phishing"):
        v = s[cle]
        print(f"{cle:20} {v['messages']:5} msg  N2+ {v['n2_et_plus_pct']:6.2f} %  N3+ {v['n3_et_plus_pct']:6.2f} %  "
              f"erreurs {v['erreurs']}  niveaux {v['niveaux_pct']}")
    print("temps (ms) :", s["temps_ms"], "| durée totale :", s["duree_totale_s"], "s")


if __name__ == "__main__":
    main()
