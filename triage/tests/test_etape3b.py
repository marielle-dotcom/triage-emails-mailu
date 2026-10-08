"""Test de bout en bout de l'étape 3b : les 10 exemples de la section 8 du document d'architecture.

Chaque exemple part de l'expéditeur de test externe (10.99.0.10) avec un domaine
de la zone DNS du lab conçu pour produire exactement les filtres attendus.

Usage : triage/tests/.venv/bin/python triage/tests/test_etape3b.py   (depuis le dossier du dépôt)
"""

import re
import sys
import time
import uuid
from email.message import EmailMessage

from labsend import delivered, dkim_sign, header_block, send_external

RCPT = "client@anac.lab"
TAG = uuid.uuid4().hex[:6]
NEUTRE = "Bonjour,\nVoici le compte rendu de la réunion de mardi.\nCordialement.\n"
URGENT = "Compte suspendu : merci d'effectuer le virement urgent aujourd'hui.\n"
URGENT_LIEN = URGENT + "Formulaire : https://bit.ly/3xYz\n"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# DKIM : "ok" = signature valide, "cassee" = message modifié après signature, None = non signé.
# (n°, scénario, domaine, nom affiché, texte, DKIM, pièce jointe, niveau, score, détections)
EXEMPLES = [
    (1, "Email légitime, tout conforme", "legitime.test", "Service", NEUTRE, "ok", None,
     0, 0, []),
    (2, "Échec SPF isolé", "spf-casse.test", "Service", NEUTRE, "ok", None,
     1, 1, ["spf"]),
    (3, "Échec SPF + DKIM", "sans-dmarc.test", "Service", NEUTRE, "cassee", None,
     1, 2, ["spf", "dkim"]),
    (4, "Typosquatting + nom affiché incohérent", "1egitime.test", "Légitime Services", NEUTRE, "ok", None,
     1, 2, ["typosquatting", "display_name_mismatch"]),
    (5, "Échec SPF + DKIM + DMARC", "tout-faux.test", "Service", NEUTRE, "cassee", None,
     2, 3, ["spf", "dkim", "dmarc"]),
    (6, "Domaine récent + mots-clés + lien masqué", "nouveau-service.test", "Service", URGENT_LIEN, "ok", None,
     2, 3, ["recent_domain", "urgency_keywords", "masked_links"]),
    (7, "3 échecs + typosquatting + nom affiché", "legitime-support.test", "Légitime Services", NEUTRE, "cassee", None,
     3, 5, ["spf", "dkim", "dmarc", "typosquatting", "display_name_mismatch"]),
    (8, "3 échecs + typosquatting + nom affiché + récent + mots-clés", "legitlme.test", "Légitime Services",
     URGENT, "cassee", None,
     4, 7, ["spf", "dkim", "dmarc", "typosquatting", "recent_domain", "urgency_keywords", "display_name_mismatch"]),
    (9, "Pièce jointe infectée (ClamAV)", "legitime.test", "Service", NEUTRE, "ok", ("eicar.txt", EICAR),
     "rejet", None, None),
    (10, "Nom d'un dirigeant + domaine typosquatté", "anac-lab.test", "Marie Durand", NEUTRE, "ok", None,
     4, 2, ["ceo_fraud", "typosquatting", "display_name_mismatch"]),
]


def construire(n, domaine, nom, texte, dkim, piece):
    m = EmailMessage()
    m["From"] = f"{nom} <contact@{domaine}>"
    m["To"] = RCPT
    m["Subject"] = f"Exemple {n} [{TAG}]"
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    m["Message-ID"] = f"<{TAG}.ex{n}@{domaine}>"
    m.set_content(texte)
    if piece:
        m.add_attachment(piece[1], maintype="text", subtype="plain", filename=piece[0])
    raw = m.as_bytes().replace(b"\n", b"\r\n")
    if dkim:
        raw = dkim_sign(raw, domaine)
    if dkim == "cassee":
        raw += b"P.S. ligne ajoutee apres la signature.\r\n"  # corps modifié : DKIM invalide
    return raw


def main():
    reponses = {}
    for n, _, domaine, nom, texte, dkim, piece, *_ in EXEMPLES:
        reponses[n] = send_external(f"contact@{domaine}", [RCPT], construire(n, domaine, nom, texte, dkim, piece))
    time.sleep(12)

    ok_total = True
    print(f"{'':6}{'n°':<4}{'Scénario':<62}{'Niveau':<8}{'Score':<7}Détections")
    for n, scenario, *_, niveau, score, detections in EXEMPLES:
        problemes, vu = [], ("-", "-", "-")
        if niveau == "rejet":
            # Mailu rejette les virus avant la file d'attente (défense native, §4.1).
            if not reponses[n].startswith("554"):
                problemes.append(f"attendu un rejet 554, obtenu {reponses[n]}")
            vu = ("rejet", "-", reponses[n][:45])
        elif reponses[n] != "250":
            problemes.append(f"réponse SMTP {reponses[n]}")
        else:
            boites = delivered(RCPT, f"{TAG}.ex{n}@")
            if len(boites) != 1:
                problemes.append(f"{len(boites)} exemplaire(s) livré(s)")
            else:
                h = header_block(boites[0])
                lire = lambda nom: (re.findall(rf"^{nom}: (.*)$", h, re.M) or ["?"])[0]  # noqa: E731
                vu = (lire("X-Risk-Level"), lire("X-Phishing-Score"), lire("X-Detection-Type"))
                attendu = (str(niveau), str(score), ",".join(detections) or "none")
                if vu != attendu:
                    problemes.append(f"attendu N{attendu[0]} / {attendu[1]} / {attendu[2]}")
                banniere = lire("X-Warning-Banner")
                if banniere != ("true" if niveau == 1 else "false"):
                    problemes.append(f"X-Warning-Banner={banniere}")
        etat = "OK " if not problemes else "ÉCHEC"
        niv = vu[0] if vu[0] in ("rejet", "-") else f"N{vu[0]}"
        print(f"{etat:<6}{n:<4}{scenario:<62}{niv:<8}{vu[1]:<7}{vu[2]}"
              + ("" if not problemes else "  — " + "; ".join(problemes)))
        ok_total &= not problemes
    print("RÉSULTAT:", "OK" if ok_total else "ÉCHEC")
    sys.exit(0 if ok_total else 1)


if __name__ == "__main__":
    main()
