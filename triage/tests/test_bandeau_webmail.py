"""Vérifie le bandeau « Prudence » dans le webmail (étape 4c).

Se connecte à Roundcube comme client@anac.lab (mot de passe lu dans
comptes-admin-client.txt), ouvre le dernier message N1 et le dernier message N0
de la boîte de réception : le bandeau doit apparaître sur le N1 seulement.

Prérequis : avoir lancé test_etape4.py (scénarios A = N0 et B = N1).
Usage : triage/tests/.venv/bin/python triage/tests/test_bandeau_webmail.py   (depuis le dossier du dépôt)
"""

import http.cookiejar
import imaplib
import re
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://mail.anac.lab"
COMPTE = "client@anac.lab"
CTX = ssl._create_unverified_context()  # certificat auto-signé du lab


def mot_de_passe():
    texte = Path("comptes-admin-client.txt").read_text(encoding="utf-8")
    return re.search(rf"{re.escape(COMPTE)}\s*\nMot de passe : (\S+)", texte).group(1)


def derniers_messages(pw):
    """{niveau: uid} du dernier message de chaque niveau dans la boîte de réception."""
    m = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=CTX)
    m.login(COMPTE, pw)
    m.select("INBOX")
    _, data = m.uid("fetch", "1:*", "(UID BODY.PEEK[HEADER.FIELDS (X-RISK-LEVEL)])")
    m.logout()
    derniers = {}
    for item in data:
        if isinstance(item, tuple):
            uid = int(re.search(rb"UID (\d+)", item[0]).group(1))
            niveau = re.search(rb"X-Risk-Level: (\d)", item[1], re.I)
            if niveau:
                derniers[niveau.group(1).decode()] = uid
    return derniers


def main():
    pw = mot_de_passe()
    uids = derniers_messages(pw)
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX),
                                     urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    op.open(BASE + "/sso/login").read()
    op.open(BASE + "/sso/login", urllib.parse.urlencode(
        {"pwned": "-1", "email": COMPTE, "pw": pw, "submitWebmail": "Sign in Webmail"}).encode()).read()
    op.open(BASE + "/webmail/").read()  # ouvre la session Roundcube

    ok = True
    for niveau, attendu in (("1", True), ("0", False)):
        if niveau not in uids:
            print(f"ÉCHEC aucun message N{niveau} dans la boîte de réception (lancer test_etape4.py)")
            ok = False
            continue
        html = op.open(f"{BASE}/webmail/?_task=mail&_action=show&_uid={uids[niveau]}&_mbox=INBOX").read().decode()
        present = 'id="triage-warning-banner"' in html
        ok &= present == attendu and "messagebody" in html
        print(f"{'OK ' if present == attendu else 'ÉCHEC'} N{niveau} (uid {uids[niveau]}) : bandeau "
              f"{'affiché' if present else 'absent'}")
    print("RÉSULTAT:", "OK" if ok else "ÉCHEC")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
