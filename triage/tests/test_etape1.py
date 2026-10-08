"""Test de bout en bout de l'étape 1 (filtre transparent).

Envoie un message MIME (UTF-8 + pièce jointe) sur le port 25 à deux
destinataires, puis vérifie dans les Maildir que chaque destinataire l'a
reçu une seule fois et que le message d'origine est intact octet pour octet.

Usage : python3 triage/tests/test_etape1.py   (depuis le dossier du dépôt, droits docker)
"""

import smtplib
import subprocess
import sys
import time
import uuid
from email.message import EmailMessage

SMTP_HOST = "127.0.0.1"
SENDER = "expediteur@exterieur.test"
RECIPIENTS = ["client@anac.lab", "user@anac.lab"]


def build_message(tag):
    msg = EmailMessage()
    msg["From"] = f"Expéditeur Test <{SENDER}>"
    msg["To"] = ", ".join(RECIPIENTS)
    msg["Subject"] = f"Étape 1 – test transparence {tag}"
    msg["Message-ID"] = f"<{tag}@exterieur.test>"
    msg.set_content("Bonjour,\n\nCorps accentué : é à ç ù — œ.\nLigne finale.\n")
    msg.add_attachment("Pièce jointe : données accentuées éàç\n".encode() * 50, maintype="text", subtype="plain", filename="notes.txt")
    # Fins de ligne CRLF comme sur le fil SMTP (sinon smtplib ajoute un CRLF final).
    return msg.as_bytes().replace(b"\n", b"\r\n")


def find_delivered(mailbox, tag):
    out = subprocess.run(
        ["docker", "exec", "mailu-imap-1", "sh", "-c", f"grep -rl '{tag}' /mail/{mailbox}/new /mail/{mailbox}/cur 2>/dev/null"],
        capture_output=True, text=True,
    ).stdout.split()
    return out


def read_file(path):
    return subprocess.run(["docker", "exec", "mailu-imap-1", "cat", path], capture_output=True).stdout


def main():
    tag = "etape1-" + uuid.uuid4().hex[:8]
    raw = build_message(tag)
    with smtplib.SMTP(SMTP_HOST, 25, timeout=30) as s:
        s.ehlo("exterieur.test")
        s.sendmail(SENDER, RECIPIENTS, raw)
    print("envoyé", tag)
    time.sleep(10)

    original = raw.replace(b"\r\n", b"\n")
    ok = True
    for rcpt in RECIPIENTS:
        files = find_delivered(rcpt, tag)
        if len(files) != 1:
            print(f"ÉCHEC {rcpt}: {len(files)} exemplaire(s) livré(s)")
            ok = False
            continue
        delivered = read_file(files[0])
        # Le message livré = en-têtes ajoutés en tête (Received, Return-Path, en-têtes Rspamd…)
        # + le message d'origine inchangé.
        headers_end = original.index(b"\n\n")
        body_ok = delivered.endswith(original[headers_end:])
        orig_headers = original[:headers_end].split(b"\n")
        headers_ok = all(h in delivered for h in orig_headers)
        print(f"{rcpt}: 1 exemplaire, corps intact={body_ok}, en-têtes d'origine présents={headers_ok}")
        ok &= body_ok and headers_ok
    print("RÉSULTAT:", "OK" if ok else "ÉCHEC")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
