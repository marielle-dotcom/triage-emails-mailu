"""Rejoue un jeu du corpus dans le Rspamd du lab (API /checkv2, analyse seule : ni livraison ni apprentissage)
et en déduit le traitement natif de Mailu : rejet (score >= 15 ou action reject), Junk (X-Spam-Level > 80 % de 15,
soit partie entière du score >= 13, seuil par défaut des utilisateurs), sinon boîte de réception.

Usage : python3 triage/evaluation/mesurer_mailu.py <annee> [nom] → resultats/<nom>.jsonl (défaut : mailu-natif-<annee>)
Adresse de Rspamd : variable RSPAMD_URL (l'IP du conteneur antispam change quand il est recréé).
"""
import email, ipaddress, json, mailbox, math, os, re, sys, time, urllib.request
from email.utils import parseaddr
from pathlib import Path

ICI = Path(__file__).resolve().parent
RSPAMD = os.environ.get("RSPAMD_URL", "http://192.168.203.5:11334/checkv2")


def ip_origine(msg):
    for rcvd in msg.get_all("Received", []):
        for ip in re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(rcvd)):
            try:
                if ipaddress.ip_address(ip).is_global:
                    return ip
            except ValueError:
                pass
    return None


def traitement(score, action):
    if action == "reject" or score >= 15:
        return "rejete"
    if math.floor(score) * 100 / 15 > 80:
        return "junk"
    return "inbox"


annee = sys.argv[1]
boite = mailbox.mbox(str(ICI / "corpus" / f"phishing-{annee}.mbox"), create=False)
nom = sys.argv[2] if len(sys.argv) > 2 else f"mailu-natif-{annee}"
sortie = open(ICI / "resultats" / f"{nom}.jsonl", "w", encoding="utf-8")
for cle in boite.iterkeys():
    raw = boite.get_bytes(cle)
    msg = email.message_from_bytes(raw)
    entetes = {"Rcpt": "jose@monkey.org"}
    ip = ip_origine(msg)
    if ip:
        entetes["IP"] = ip
    exp = parseaddr(str(msg.get("Return-Path", "")))[1]
    if exp:
        entetes["From"] = exp
    t0 = time.time()
    try:
        d = json.load(urllib.request.urlopen(urllib.request.Request(RSPAMD, data=raw, headers=entetes), timeout=60))
        ligne = {"id": f"phishing-{annee}/{cle}", "ip": ip, "score": d.get("score"), "action": d.get("action"),
                 "mailu": traitement(d.get("score", 0), d.get("action")), "symboles": sorted(d.get("symbols", {}))}
    except Exception as e:
        ligne = {"id": f"phishing-{annee}/{cle}", "ip": ip, "erreur": str(e)}
    ligne["s"] = round(time.time() - t0, 2)
    sortie.write(json.dumps(ligne, ensure_ascii=False) + "\n"); sortie.flush()
