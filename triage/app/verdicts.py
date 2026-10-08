"""Lecture des verdicts natifs de Mailu (Rspamd, ClamAV) — jamais recalculés.

Constats sur Mailu 2024.06 (étape 2) :
- Rspamd ajoute en tête du message « Authentication-Results: mail.anac.lab; … »
  et supprime ceux envoyés par l'expéditeur ; on ne lit quand même que le
  premier en-tête portant notre identifiant (défense en profondeur) ;
- un mail sans vérification possible porte « Authentication-Results: mail.anac.lab; none » ;
- l'en-tête antivirus s'appelle X-Virus (pas X-Virus-Status) ; en pratique
  Rspamd rejette les virus avant la file d'attente ;
- le score de spam est donné par X-Spamd-Bar (pas de X-Spamd-Result).
"""

import os
import re
from dataclasses import asdict, dataclass, field

from headers import parse_headers

AUTHSERV_ID = os.environ.get("TRIAGE_AUTHSERV_ID", "mail.anac.lab").lower()
# Choix validé : seul « fail » compte ; mettre à true pour compter aussi « softfail ».
SPF_SOFTFAIL_COUNTS = os.environ.get("TRIAGE_SPF_SOFTFAIL_COUNTS", "false").lower() == "true"

_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


@dataclass
class NativeVerdicts:
    spf: str = "absent"
    dkim: str = "absent"
    dmarc: str = "absent"
    authres_found: bool = False
    virus: bool = False
    virus_detail: str = ""
    spam_bar: str = ""
    points: dict = field(default_factory=dict)

    @property
    def auth_points(self):
        return sum(self.points.values())

    def as_log(self):
        data = asdict(self)
        data["auth_points"] = self.auth_points
        return data


def _first_trusted_authres(msg):
    """Premier Authentication-Results dont l'identifiant de serveur est le nôtre."""
    for value in msg.get_all("Authentication-Results", []):
        text = " ".join(str(value).split())
        authserv_id = text.split(";", 1)[0].strip().lower()
        if authserv_id == AUTHSERV_ID:
            return text
    return None


def _combine(results):
    """Plusieurs résultats pour une méthode (ex. 2 signatures DKIM) : pass l'emporte."""
    if not results:
        return "absent"
    if "pass" in results:
        return "pass"
    return results[0]


def read_native_verdicts(raw):
    msg = parse_headers(raw)
    v = NativeVerdicts()

    authres = _first_trusted_authres(msg)
    if authres is not None:
        v.authres_found = True
        found = {"spf": [], "dkim": [], "dmarc": []}
        for method, result in _RESULT_RE.findall(authres.split(";", 1)[1] if ";" in authres else ""):
            found[method.lower()].append(result.lower())
        v.spf, v.dkim, v.dmarc = (_combine(found[m]) for m in ("spf", "dkim", "dmarc"))

    spf_fail = {"fail", "softfail"} if SPF_SOFTFAIL_COUNTS else {"fail"}
    v.points = {
        "spf": int(v.spf in spf_fail),
        "dkim": int(v.dkim == "fail"),
        "dmarc": int(v.dmarc == "fail"),
    }

    virus = msg.get("X-Virus")
    if virus:
        v.virus = True
        v.virus_detail = " ".join(str(virus).split())

    v.spam_bar = str(msg.get("X-Spamd-Bar", "")).strip()
    return v
