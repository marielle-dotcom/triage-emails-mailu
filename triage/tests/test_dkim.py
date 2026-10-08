"""Test de bout en bout : l'ajout des en-têtes de triage ne casse pas la signature DKIM.

Envoie depuis l'expéditeur externe (10.99.0.10) des mails signés DKIM par legitime.test,
avec les deux canonicalisations (simple/simple, la plus stricte, et relaxed/relaxed),
puis vérifie la signature sur le message tel qu'il est livré dans la boîte, après
passage dans le filtre. Contrôle négatif : un mail modifié après signature doit
être détecté comme invalide, preuve que la vérification est réelle.
La clé publique est lue dans la zone DNS du lab (overrides/unbound/lab-zones.conf).

Usage : triage/tests/.venv/bin/python triage/tests/test_dkim.py   (depuis le dossier du dépôt)
"""

import re
import sys
import time
import uuid
from email.message import EmailMessage
from pathlib import Path

import dkim

from labsend import DKIM_KEY, header_block, locate, send_external

TAG = uuid.uuid4().hex[:6]
DOMAINE = "legitime.test"
DESTINATAIRE = "client@anac.lab"
ZONES = Path(__file__).resolve().parents[2] / "overrides" / "unbound" / "lab-zones.conf"
ENTETES_SIGNES = [b"from", b"to", b"subject", b"date", b"message-id"]
ENTETES_TRIAGE = ("X-Risk-Level", "X-Phishing-Score", "X-Detection-Type", "X-Warning-Banner")

# (code, canonicalisation, message modifié après signature, signature attendue valide)
SCENARIOS = [
    ("simple", (b"simple", b"simple"), False, True),
    ("relaxed", (b"relaxed", b"relaxed"), False, True),
    ("modifie", (b"simple", b"simple"), True, False),
]


def cle_publique():
    m = re.search(r'lab\._domainkey\.legitime\.test\. TXT "([^"]+)"', ZONES.read_text())
    return m.group(1).encode()


def construire(code, canon, modifie):
    m = EmailMessage()
    m["From"] = f"Service <contact@{DOMAINE}>"
    m["To"] = DESTINATAIRE
    m["Subject"] = f"Test DKIM {code} [{TAG}]"
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    m["Message-ID"] = f"<{TAG}.{code}@{DOMAINE}>"
    m.set_content("Bonjour,\nCompte rendu de la réunion de mardi.\nCordialement.\n")
    raw = m.as_bytes().replace(b"\n", b"\r\n")
    raw = dkim.sign(raw, b"lab", DOMAINE.encode(), DKIM_KEY.read_bytes(),
                    canonicalize=canon, include_headers=ENTETES_SIGNES) + raw
    if modifie:
        raw += b"Ligne ajoutee apres la signature.\r\n"
    return raw


def main():
    txt = cle_publique()
    reponses = {code: send_external(f"contact@{DOMAINE}", [DESTINATAIRE], construire(code, canon, modifie))
                for code, canon, modifie, _ in SCENARIOS}
    time.sleep(12)

    ok_total = True
    for code, canon, _, attendu in SCENARIOS:
        problemes = []
        if reponses[code] != "250":
            problemes.append(f"réponse SMTP {reponses[code]}")
        trouves = locate(DESTINATAIRE, f"{TAG}.{code}@")
        if len(trouves) != 1:
            problemes.append(f"{len(trouves)} exemplaire(s) livré(s) au lieu de 1")
            valide = None
        else:
            livre = trouves[0][1]
            entetes = header_block(livre)
            absents = [h for h in ENTETES_TRIAGE if not re.search(rf"^{h}: ", entetes, re.M)]
            if absents:
                problemes.append(f"en-têtes de triage absents : {absents} (le mail n'est pas passé par le filtre)")
            crlf = livre.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            valide = dkim.verify(crlf, dnsfunc=lambda name, timeout=5: txt)
            if valide != attendu:
                problemes.append(f"signature {'valide' if valide else 'invalide'}, attendue "
                                 f"{'valide' if attendu else 'invalide'}")
        print(f"{'OK ' if not problemes else 'ÉCHEC'} {code:<8} c={canon[0].decode()}/{canon[1].decode()} "
              f"signature après filtre : {valide}" + ("" if not problemes else " — " + "; ".join(problemes)))
        ok_total &= not problemes
    print("RÉSULTAT:", "OK" if ok_total else "ÉCHEC")
    sys.exit(0 if ok_total else 1)


if __name__ == "__main__":
    main()
