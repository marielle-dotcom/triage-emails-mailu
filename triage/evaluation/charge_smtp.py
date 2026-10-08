"""Banc B (robustesse) de l'étape 6 : envoie des mails réels des corpus à travers Mailu.

50 légitimes et 50 phishing du jeu de test, en-têtes et corps intacts, depuis
l'expéditeur externe du lab (un seul conteneur, une connexion SMTP par message) vers
evaluation@anac.lab (boîte temporaire). L'adresse d'enveloppe est celle d'un domaine
du lab (contact@sansauth.test) : les domaines d'origine des corpus n'existent souvent
plus et Postfix refuserait l'expéditeur (« Domain not found »).
Mesure : réponses SMTP, erreurs du filtre, réponses 451, débit (logs du filtre).

Usage : triage/tests/.venv/bin/python triage/evaluation/charge_smtp.py   (depuis le dossier du dépôt)
"""

import json
import subprocess
import tempfile
import sys
import time
from collections import Counter
from pathlib import Path

ICI = Path(__file__).resolve().parent
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parent / "tests"))
import evaluer  # noqa: E402
from labsend import FRONT_IP, SENDER_IMAGE, SENDER_IP, SENDER_NETWORK  # noqa: E402

DEST = "evaluation@anac.lab"
ENVELOPPE = "contact@sansauth.test"
ENVOI = """
import json, pathlib, smtplib, time
res = []
for f in sorted(pathlib.Path("/lot").glob("*.eml")):
    t = time.time()
    try:
        with smtplib.SMTP("%s", 25, timeout=60) as s:
            s.ehlo("sansauth.test")
            s.sendmail("%s", ["%s"], f.read_bytes())
        code = "250"
    except smtplib.SMTPResponseException as e:
        code = str(e.smtp_code)
    except smtplib.SMTPRecipientsRefused as e:
        code = str(list(e.recipients.values())[0][0])
    except Exception as e:
        code = type(e).__name__
    res.append([f.stem, code, round(time.time() - t, 3)])
print(json.dumps(res))
""" % (FRONT_IP, ENVELOPPE, DEST)


def main():
    lot = {"legitime": [], "phishing": []}
    for classe, jeu, ident, raw in evaluer.messages():
        if jeu == "test" and len(lot[classe]) < 50:
            lot[classe].append((ident, raw))
    dossier = Path(tempfile.mkdtemp(prefix="charge-"))
    for classe, messages in lot.items():
        for i, (ident, raw) in enumerate(messages):
            (dossier / f"{classe}-{i:03}.eml").write_bytes(raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    dossier.chmod(0o755)
    for f in dossier.iterdir():
        f.chmod(0o644)
    debut = time.strftime("%Y-%m-%dT%H:%M:%S")
    t0 = time.time()
    sortie = subprocess.run(["docker", "run", "--rm", "--network", SENDER_NETWORK, "--ip", SENDER_IP,
                             "-v", f"{dossier}:/lot:ro", SENDER_IMAGE, "/venv/bin/python", "-c", ENVOI],
                            capture_output=True, text=True).stdout
    duree = time.time() - t0
    resultats = json.loads(sortie.strip().splitlines()[-1])
    reponses = Counter((nom.split("-")[0], code) for nom, code, _ in resultats)
    time.sleep(15)
    logs = subprocess.run(["docker", "logs", "--since", debut, "mailu-triage-1"], capture_output=True, text=True).stdout
    entrees = [json.loads(l) for l in logs.splitlines() if l.startswith("{")]
    traites = [e for e in entrees if e.get("msg") in ("message réinjecté", "message mis en quarantaine")
               and DEST in e.get("rcpt_to", [])]
    erreurs = [e for e in entrees if e.get("level") in ("ERROR", "CRITICAL") or "échouée" in e.get("msg", "")]
    smtp = subprocess.run(["docker", "logs", "--since", debut, "mailu-smtp-1"], capture_output=True, text=True).stdout
    print("réponses SMTP :", dict(reponses))
    print(f"envoi de {len(resultats)} messages : {duree:.0f} s ({len(resultats) / duree:.1f} msg/s) ; "
          f"messages analysés par le filtre : {len(traites)}")
    print("niveaux attribués :", dict(Counter(e["decision"]["level"] for e in traites)))
    print("erreurs du filtre :", len(erreurs), [e.get("msg") for e in erreurs][:5])
    print("réponses 451 du filtre vues par Postfix :", smtp.count("Triage temporarily unavailable"))


if __name__ == "__main__":
    main()
