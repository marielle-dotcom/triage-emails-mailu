"""Manipulation des en-têtes directement sur le message brut.

Le message n'est jamais parsé puis resérialisé : seules les lignes d'en-tête
visées sont retirées, le reste (en-têtes, corps, structure MIME) reste
identique octet pour octet, ce qui préserve les signatures DKIM.
"""

from email.parser import BytesHeaderParser
from email.policy import default as default_policy

# En-têtes posés par le système de triage : tout exemplaire présent à
# l'arrivée a été ajouté par l'expéditeur et doit être supprimé (§6).
# X-Original-Recipient (étape 4) désigne le destinataire à qui libérer un message en
# quarantaine : un exemplaire forgé pourrait détourner la libération.
TRIAGE_HEADERS = ("x-risk-level", "x-phishing-score", "x-detection-type", "x-warning-banner",
                  "x-original-recipient")


def split_message(raw):
    """Sépare (en-têtes, séparateur + corps). Accepte CRLF ou LF."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx + len(sep) // 2], raw[idx + len(sep) // 2:]
    return raw, b""


def _fields(header_block):
    """Découpe le bloc d'en-têtes en champs (ligne + lignes de continuation)."""
    fields = []
    for line in header_block.splitlines(keepends=True):
        if line[:1] in (b" ", b"\t") and fields:
            fields[-1] += line
        else:
            fields.append(line)
    return fields


def field_name(field):
    return field.split(b":", 1)[0].strip().lower().decode("ascii", errors="replace")


def strip_headers(raw, names=TRIAGE_HEADERS):
    """Retire les champs dont le nom est dans `names` ; renvoie (message, noms retirés)."""
    names = {n.lower() for n in names}
    header_block, rest = split_message(raw)
    kept, removed = [], []
    for field in _fields(header_block):
        if field_name(field) in names:
            removed.append(field_name(field))
        else:
            kept.append(field)
    if not removed:
        return raw, []
    return b"".join(kept) + rest, removed


def parse_headers(raw):
    """Objet Message ne contenant que les en-têtes, dans l'ordre du message (le plus récent en premier)."""
    header_block, _ = split_message(raw)
    return BytesHeaderParser(policy=default_policy).parsebytes(header_block + b"\r\n")


def ajouter_entetes(raw, entetes):
    """Ajoute les en-têtes en tête du message brut, sans toucher au reste (§6)."""
    fin = b"\r\n" if b"\r\n" in raw[:2000] else b"\n"
    bloc = b"".join(f"{nom}: {valeur}".encode("ascii", errors="replace") + fin
                    for nom, valeur in entetes.items())
    return bloc + raw
