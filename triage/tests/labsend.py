"""Outils communs aux tests : envoi « externe », signature DKIM, lecture des Maildir.

Rspamd traite le réseau Docker de Mailu (192.168.203.0/24) comme local et n'y
vérifie ni SPF, ni DKIM, ni DMARC. Les mails de test partent donc d'un
conteneur jetable sur le réseau séparé « lab-externe » (10.99.0.10), vers le
conteneur front (10.99.0.2:25) sans NAT : le port publié sur l'hôte ferait
apparaître tous les envois depuis 192.168.203.1 (docker-proxy), donc « locaux ».
"""

import json
import re
import subprocess
import time
from email.message import EmailMessage
from pathlib import Path

import dkim

FRONT_IP = "10.99.0.2"
SENDER_NETWORK = "mailu_lab-externe"
SENDER_IP = "10.99.0.10"
SENDER_IMAGE = "mailu-triage:scenario-a"
DKIM_KEY = Path(__file__).parent / "dkim" / "legitime.test.lab.key"

_SEND_SCRIPT = """
import json, smtplib, sys
args = json.loads(sys.argv[1])
raw = sys.stdin.buffer.read()
try:
    with smtplib.SMTP(args["host"], 25, timeout=30) as s:
        s.ehlo(args["helo"])
        s.sendmail(args["mail_from"], args["rcpts"], raw)
    print("250")
except smtplib.SMTPResponseException as e:
    print(e.smtp_code, e.smtp_error.decode(errors="replace"))
except smtplib.SMTPRecipientsRefused as e:
    print("RCPT", e.recipients)
"""


def build(from_header, to, subject, body="Message de test.\n", extra_headers=()):
    msg = EmailMessage()
    msg["From"] = from_header
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
    for name, value in extra_headers:
        msg[name] = value
    msg.set_content(body)
    return msg.as_bytes().replace(b"\n", b"\r\n")


def dkim_sign(raw, domain, selector=b"lab"):
    sig = dkim.sign(raw, selector, domain.encode(), DKIM_KEY.read_bytes(),
                    include_headers=[b"from", b"to", b"subject", b"date"])
    return sig + raw


def send_external(mail_from, rcpts, raw, helo=None):
    """Envoie depuis 10.99.0.10 ; renvoie la réponse SMTP finale (« 250 » si accepté)."""
    args = {"host": FRONT_IP, "mail_from": mail_from, "rcpts": rcpts,
            "helo": helo or mail_from.split("@")[-1]}
    out = subprocess.run(
        ["docker", "run", "--rm", "-i", "--network", SENDER_NETWORK, "--ip", SENDER_IP,
         SENDER_IMAGE, "/venv/bin/python", "-c", _SEND_SCRIPT, json.dumps(args)],
        input=raw, capture_output=True,
    )
    return (out.stdout or out.stderr).decode(errors="replace").strip()


def _lire(conteneur, fichiers):
    return {f: subprocess.run(["docker", "exec", conteneur, "cat", f], capture_output=True).stdout for f in fichiers}


def _chercher(conteneur, dossiers, marker):
    script = (f"for f in $(find {dossiers} -type f \\( -path '*/cur/*' -o -path '*/new/*' -o -name '*.eml' \\) "
              f"2>/dev/null); do grep -l '{marker}' \"$f\"; done 2>/dev/null")
    return subprocess.run(["docker", "exec", conteneur, "sh", "-c", script], capture_output=True, text=True).stdout.split()


def locate(mailbox, marker):
    """[(dossier, contenu brut)] des messages contenant `marker` destinés à `mailbox`.

    Cherche dans tous les dossiers de la boîte (INBOX, Suspect…) et, depuis
    l'étape 5, dans le stockage de quarantaine séparé (conteneur du filtre,
    /quarantaine) les messages dont X-Original-Recipient est `mailbox` ;
    ceux-ci sont rangés sous « quarantaine/N3 » ou « quarantaine/N4 ».
    """
    found = []
    for f, raw in _lire("mailu-imap-1", _chercher("mailu-imap-1", f"/mail/{mailbox}", marker)).items():
        sub = f.split("/")[3]  # /mail/<boîte>/<dossier Maildir ou cur|new>/...
        found.append((sub[1:] if sub.startswith(".") else "INBOX", raw))
    for f, raw in _lire("mailu-triage-1", _chercher("mailu-triage-1", "/quarantaine", marker)).items():
        entetes = raw.split(b"\r\n\r\n", 1)[0]
        if f"X-Original-Recipient: {mailbox}".encode() not in entetes:
            continue
        niveau = re.search(rb"^X-Risk-Level: (\d)", entetes, re.M)
        # Le stockage garde le message tel que reçu en SMTP (CRLF) ; les boîtes Dovecot
        # sont en LF : on normalise pour comparer de la même façon partout.
        found.append((f"quarantaine/N{niveau.group(1).decode() if niveau else '?'}", raw.replace(b"\r\n", b"\n")))
    return found


def delivered(mailbox, marker):
    """Contenu brut des messages livrés à `mailbox` (tous dossiers, quarantaine comprise)."""
    return [raw for _, raw in locate(mailbox, marker)]


def header_block(raw):
    return raw.split(b"\n\n", 1)[0].decode(errors="replace")
