"""Outils communs sur les noms de domaine (typosquatting, nom affiché, dirigeants)."""

import unicodedata

# Caractères souvent substitués pour imiter un domaine : chiffres, lettres
# d'autres alphabets (cyrillique, grec) et paires de lettres trompeuses.
SOSIES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "!": "i", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k",
}
PAIRES = {"rn": "m", "vv": "w", "cl": "d"}


def unicode_domaine(domaine):
    """Décode les domaines internationalisés (xn--…) pour comparer les vrais caractères."""
    try:
        return domaine.encode("ascii").decode("idna").lower()
    except (UnicodeError, ValueError):
        return domaine.lower()


def squelette(domaine):
    """Forme « visuelle » d'un domaine : i → l, 0 → o, rn → m, cyrillique → latin…"""
    d = unicodedata.normalize("NFKD", unicode_domaine(domaine))
    d = "".join(SOSIES.get(c, c) for c in d if not unicodedata.combining(c))  # sans accents
    for paire, lettre in PAIRES.items():
        d = d.replace(paire, lettre)
    return d.replace("i", "l")


def distance(a, b):
    """Distance de Damerau-Levenshtein restreinte (insertions, suppressions, substitutions, inversions)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cout = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cout)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def appartient(domaine, parent):
    """domaine == parent, ou sous-domaine de parent."""
    return domaine == parent or domaine.endswith("." + parent)


def libelle(domaine):
    """Partie principale : « legitime » pour legitime.test, « anac » pour mail.anac.lab."""
    morceaux = domaine.split(".")
    return morceaux[-2] if len(morceaux) >= 2 else domaine


def est_interne(domaine, referentiels):
    internes = referentiels.get("organisations", {}).get("domaines_internes", [])
    return any(appartient(domaine, d) for d in internes)


def domaines_proteges(referentiels):
    return [d for org in referentiels.get("organisations", {}).get("organisations", [])
            for d in org.get("domaines", [])]
