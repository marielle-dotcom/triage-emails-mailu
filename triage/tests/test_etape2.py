"""Test de bout en bout de l'étape 2 (verdicts natifs + en-têtes forgés).

Chaque scénario part de l'expéditeur de test externe (10.99.0.10, réseau
lab-externe), traverse Mailu puis le filtre, et l'on vérifie :
- la réponse SMTP ;
- les verdicts journalisés par le filtre (docker logs mailu-triage-1) ;
- dans la boîte : en-têtes de triage forgés absents, corps intact.

Usage : triage/tests/.venv/bin/python triage/tests/test_etape2.py   (depuis le dossier du dépôt)
"""

import json
import subprocess
import sys
import time
import uuid

from labsend import build, delivered, dkim_sign, header_block, send_external

RCPT = "client@anac.lab"
TAG = uuid.uuid4().hex[:6]

# (nom, domaine, signer DKIM, altérer après signature, en-têtes ajoutés, verdict attendu, points attendus)
SCENARIOS = [
    ("tout conforme", "legitime.test", True, False, [], ("pass", "pass", "pass"), 0),
    ("DKIM cassé (corps modifié après signature)", "legitime.test", True, True, [], ("pass", "fail", "pass"), 1),
    ("SPF + DMARC en échec", "usurpe.test", False, False, [], ("fail", "none", "fail"), 2),
    ("DMARC p=reject non rejeté par Mailu", "usurpe-strict.test", False, False, [], ("fail", "none", "fail"), 2),
    ("SPF softfail (ne compte pas)", "softfail.test", False, False, [], ("softfail", "none", "fail"), 1),
    ("aucune authentification publiée", "sansauth.test", False, False, [], ("none", "none", "none"), 0),
    ("en-têtes forgés par l'expéditeur", "usurpe.test", False, False,
     [("X-Risk-Level", "0"), ("X-Phishing-Score", "0"), ("X-Warning-Banner", "false"),
      ("Authentication-Results", "mail.anac.lab; spf=pass; dkim=pass; dmarc=pass")],
     ("fail", "none", "fail"), 2),
]


def triage_logs(since):
    out = subprocess.run(["docker", "logs", "--since", since, "mailu-triage-1"],
                         capture_output=True, text=True).stdout
    entries = []
    for line in out.splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return entries


def main():
    start = time.strftime("%Y-%m-%dT%H:%M:%S")
    sent = []
    for i, (name, dom, sign, alter, extra, expected, points) in enumerate(SCENARIOS):
        mid = f"<{TAG}.{i}@{dom}>"
        raw = build(f"Service <contact@{dom}>", RCPT, f"etape2 {TAG} #{i} {name}",
                    body=f"Scénario {i} : {name}\n", extra_headers=[("Message-ID", mid), *extra])
        if sign:
            raw = dkim_sign(raw, dom)
        if alter:
            raw = raw.replace("Scénario".encode(), b"SCENARIO-MODIFIE")
        reply = send_external(f"contact@{dom}", [RCPT], raw)
        sent.append((i, name, mid, raw, reply, expected, points))
    time.sleep(10)

    logs = {e.get("message_id"): e for e in triage_logs(start) if e.get("msg") == "message réinjecté"}
    ok_all = True
    for i, name, mid, raw, reply, expected, points in sent:
        problems = []
        if reply != "250":
            problems.append(f"réponse SMTP {reply}")
        entry = logs.get(mid)
        if not entry:
            problems.append("absent des logs du filtre")
        else:
            n = entry["native"]
            got = (n["spf"], n["dkim"], n["dmarc"])
            if got != expected:
                problems.append(f"verdicts {got} au lieu de {expected}")
            if n["auth_points"] != points:
                problems.append(f"{n['auth_points']} point(s) au lieu de {points}")
        boxes = delivered(RCPT, mid.strip("<>"))
        if len(boxes) != 1:
            problems.append(f"{len(boxes)} exemplaire(s) livré(s)")
        else:
            hdrs = header_block(boxes[0]).lower()
            # Depuis l'étape 3, le filtre pose ses propres en-têtes : il doit y en
            # avoir exactement un de chaque (un exemplaire forgé en ferait deux).
            for header in ("x-risk-level:", "x-phishing-score:", "x-warning-banner:"):
                count = sum(1 for line in hdrs.splitlines() if line.startswith(header))
                if count != 1:
                    problems.append(f"{header} présent {count} fois")
            sent_body = raw.replace(b"\r\n", b"\n").split(b"\n\n", 1)[1]
            if not boxes[0].endswith(sent_body):
                problems.append("corps modifié")
        status = "OK " if not problems else "ÉCHEC"
        detail = "" if not problems else " — " + "; ".join(problems)
        summary = ""
        if entry:
            n = entry["native"]
            summary = f" [spf={n['spf']} dkim={n['dkim']} dmarc={n['dmarc']} points={n['auth_points']}" \
                      f" retirés={entry['forged_headers_removed']}]"
        print(f"{status} #{i} {name}{summary}{detail}")
        ok_all &= not problems
    print("RÉSULTAT:", "OK" if ok_all else "ÉCHEC")
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
