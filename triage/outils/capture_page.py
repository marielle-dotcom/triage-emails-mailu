"""Capture d'écran d'une page authentifiée (Grafana ou outil de quarantaine) via Chromium sans interface.

Usage : triage/tests/.venv/bin/python triage/outils/capture_page.py <url de connexion> <cookie> <fichier.png> <url à capturer> <identifiants JSON>
"""
import base64, json, subprocess, sys, time, urllib.request, urllib.parse, http.cookiejar
import websocket
url_login, cookie_name, sortie, cible = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
login_data = json.loads(sys.argv[5])
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
if login_data.get("_json"):
    req = urllib.request.Request(url_login, json.dumps(login_data["_json"]).encode(), {"Content-Type": "application/json"})
    op.open(req).read()
else:
    import re
    page = op.open(url_login).read().decode()
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    op.open(url_login, urllib.parse.urlencode({**login_data["_form"], "csrf": csrf}).encode()).read()
cookies = [c for c in jar if c.name == cookie_name]
proc = subprocess.Popen(["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--remote-debugging-port=9333",
                         "--window-size=1400,1700", "--user-data-dir=/tmp/claude-1000/chrome-capture", "about:blank"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(40):
        try:
            tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9333/json")); break
        except Exception: time.sleep(0.5)
    ws = websocket.create_connection([t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"], suppress_origin=True)
    n = iter(range(1, 1000))
    def cmd(method, **params):
        i = next(n); ws.send(json.dumps({"id": i, "method": method, "params": params}))
        while True:
            r = json.loads(ws.recv())
            if r.get("id") == i: return r.get("result", {})
    cmd("Network.enable")
    for c in cookies:
        cmd("Network.setCookie", name=c.name, value=c.value, domain=c.domain.lstrip("."), path=c.path or "/")
    cmd("Emulation.setDeviceMetricsOverride", width=1400, height=1700, deviceScaleFactor=1, mobile=False)
    cmd("Page.enable"); cmd("Page.navigate", url=cible); time.sleep(12)
    data = cmd("Page.captureScreenshot", format="png")["data"]
    open(sortie, "wb").write(base64.b64decode(data)); print("capture", sortie)
finally:
    proc.terminate()
