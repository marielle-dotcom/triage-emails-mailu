"""Session de l'outil de quarantaine : cookie de session, inactivité de 15 min, durée maximale de 8 h.

S'exécute dans l'image de l'outil (fastapi n'est pas dans le venv des tests) :
  docker run --rm -v "$PWD/triage/tests:/tests:ro" -e TRIAGE_UI_SECRET=test \
    -e TRIAGE_UI_ADMINS=administrateur@anac.lab --entrypoint sh mailu-triage-ui:session \
    -c '/venv/bin/pip install -q --target /tmp/dep httpx pytest && PYTHONPATH=/tmp/dep:/app /venv/bin/python -m pytest -q -p no:cacheprovider /tests/test_unit_session_ui.py'
"""

import re

import pytest
from fastapi.testclient import TestClient

import main

ADMIN = "administrateur@anac.lab"


class Horloge:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def client(monkeypatch):
    horloge = Horloge()
    monkeypatch.setattr(main.time, "time", horloge)
    monkeypatch.setattr(main, "authentifier", lambda email, mdp: email == ADMIN and mdp == "bon")
    monkeypatch.setattr(main.donnees, "liste", lambda etat: [])
    c = TestClient(main.app, follow_redirects=False)
    c.horloge = horloge
    return c


def connecter(c):
    page = c.get("/connexion").text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    r = c.post("/connexion", data={"email": ADMIN, "mot_de_passe": "bon", "csrf": csrf})
    assert r.headers["location"] == "/quarantaine"
    return r


def test_cookie_de_session_sans_date_d_expiration(client):
    r = connecter(client)
    cookie = r.headers["set-cookie"].lower()
    assert "triage_session=" in cookie
    assert "max-age" not in cookie and "expires" not in cookie
    assert "samesite=strict" in cookie and "httponly" in cookie


def test_session_valide_avant_15_minutes(client):
    connecter(client)
    client.horloge.t += 14 * 60
    assert client.get("/quarantaine").status_code == 200


def test_inactivite_de_15_minutes_deconnecte(client):
    connecter(client)
    client.horloge.t += 15 * 60 + 1
    r = client.get("/quarantaine")
    assert r.headers["location"] == "/connexion"
    assert "Session expirée" in client.get("/connexion").text
    # le message n'est affiché qu'une fois, et la session reste fermée
    assert "Session expirée" not in client.get("/connexion").text
    assert client.get("/quarantaine").headers["location"] == "/connexion"


def test_chaque_action_repousse_l_inactivite(client):
    connecter(client)
    for _ in range(4):
        client.horloge.t += 10 * 60
        assert client.get("/quarantaine").status_code == 200


def test_duree_maximale_de_8_heures_meme_si_actif(client):
    connecter(client)
    for _ in range(8 * 6):
        client.horloge.t += 10 * 60
        client.get("/quarantaine")
    client.horloge.t += 60
    assert client.get("/quarantaine").headers["location"] == "/connexion"


def test_ancienne_session_sans_horodatage_refusee(client):
    # cookie émis par l'ancienne version (utilisateur seul, sans horodatage) : refusé
    from itsdangerous import TimestampSigner
    import base64, json
    donnees = base64.b64encode(json.dumps({"utilisateur": ADMIN}).encode())
    client.cookies.set("triage_session", TimestampSigner("test").sign(donnees).decode())
    assert client.get("/quarantaine").headers["location"] == "/connexion"
