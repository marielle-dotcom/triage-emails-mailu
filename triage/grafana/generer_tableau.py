"""Génère le tableau de bord Grafana du système de triage (dashboards/triage.json).

Usage : python3 triage/grafana/generer_tableau.py   (depuis ~/system), puis reconstruire
l'image : docker compose up -d --build triage-grafana

Couleurs des niveaux N0 à N4 : une seule teinte bleue, du clair au foncé (rampe
ordinale validée pour la lisibilité et le daltonisme) ; une seule couleur pour les
graphiques à une série.
"""

import json
from pathlib import Path

DS = {"type": "grafana-postgresql-datasource", "uid": "triage-pg"}
NIV = [("N0 Sain", "#86b6ef"), ("N1 Faible", "#5598e7"), ("N2 Moyen", "#2a78d6"), ("N3 Élevé", "#1c5cab"),
       ("N4 Critique", "#104281")]
UNE = "#2a78d6"
LIBELLES = {"spf": "Échec SPF", "dkim": "Échec DKIM", "dmarc": "Échec DMARC", "typosquatting": "Typosquatting",
            "recent_domain": "Domaine récent", "urgency_keywords": "Mots-clés d'urgence", "masked_links": "Liens masqués",
            "suspicious_attachment": "Pièce jointe suspecte", "display_name_mismatch": "Nom affiché incohérent",
            "ceo_fraud": "Usurpation de dirigeant (N4 direct)", "virus": "Virus (N4 direct)"}
pid = iter(range(1, 100))


def cible(sql, fmt="table"):
    return [{"refId": "A", "datasource": DS, "rawSql": sql, "format": fmt, "rawQuery": True, "editorMode": "code"}]


def stat(titre, sql, x, desc):
    return {"id": next(pid), "type": "stat", "title": titre, "description": desc, "datasource": DS,
            "gridPos": {"h": 4, "w": 6, "x": x, "y": 0}, "targets": cible(sql),
            "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": "text"}, "unit": "none", "decimals": 0},
                            "overrides": []},
            "options": {"colorMode": "none", "graphMode": "none", "textMode": "value", "justifyMode": "center",
                        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}}


def barres(titre, sql, x, y, w, desc, champ):
    return {"id": next(pid), "type": "barchart", "title": titre, "description": desc, "datasource": DS,
            "gridPos": {"h": 9, "w": w, "x": x, "y": y}, "targets": cible(sql),
            "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": UNE}, "unit": "none", "decimals": 0,
                                         "custom": {"fillOpacity": 100, "lineWidth": 0, "axisSoftMin": 0}}, "overrides": []},
            "options": {"orientation": "horizontal", "xField": champ, "showValue": "always", "barWidth": 0.6,
                        "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom"},
                        "tooltip": {"mode": "single"}, "text": {"valueSize": 12}}}


def tableau(titre, sql, y, desc, liens=None):
    p = {"id": next(pid), "type": "table", "title": titre, "description": desc, "datasource": DS,
         "gridPos": {"h": 9, "w": 24, "x": 0, "y": y}, "targets": cible(sql),
         "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}}}, "overrides": []},
         "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}}
    if liens:
        p["fieldConfig"]["overrides"].append({"matcher": {"id": "byName", "options": liens[0]},
            "properties": [{"id": "links", "value": [{"title": "Ouvrir dans l'outil de quarantaine", "url": liens[1]}]}]})
    return p


panels = [
    stat("Messages analysés", "SELECT count(*) AS \"messages\" FROM decisions WHERE $__timeFilter(recu_le)", 0,
         "Messages entrants traités par le filtre sur la période."),
    stat("Classés Suspect (N2)", "SELECT count(*) FROM decisions WHERE $__timeFilter(recu_le) AND niveau = 2", 6,
         "Messages livrés dans le dossier Suspect sur la période."),
    stat("Mis en quarantaine (N3, N4)",
         "SELECT count(*) FROM decisions WHERE $__timeFilter(recu_le) AND action = 'quarantaine'", 12,
         "Messages retenus dans le stockage de quarantaine sur la période."),
    stat("Quarantaines à valider", "SELECT count(*) FROM decisions WHERE action = 'quarantaine' AND etat = 'en_attente'",
         18, "Quarantaines en attente de décision de l'équipe sécurité (toutes dates)."),
]
sql_niv = ("SELECT $__timeGroupAlias(recu_le, '1d'), "
           + ", ".join(f"count(*) FILTER (WHERE niveau = {i}) AS \"{nom}\"" for i, (nom, _) in enumerate(NIV))
           + " FROM decisions WHERE $__timeFilter(recu_le) GROUP BY 1 ORDER BY 1")
panels.append({"id": next(pid), "type": "timeseries", "title": "Messages par niveau de criticité et par jour",
               "description": "Nombre de messages par jour, empilés par niveau (N0 clair à N4 foncé).",
               "datasource": DS, "gridPos": {"h": 9, "w": 24, "x": 0, "y": 4}, "targets": cible(sql_niv, "time_series"),
               "fieldConfig": {"defaults": {"unit": "none", "decimals": 0,
                                            "custom": {"drawStyle": "bars", "fillOpacity": 100, "lineWidth": 1,
                                                       "barAlignment": 0, "stacking": {"mode": "normal", "group": "A"},
                                                       "showPoints": "never", "axisSoftMin": 0, "gradientMode": "none"}},
                               "overrides": [{"matcher": {"id": "byName", "options": nom},
                                              "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
                                             for nom, c in NIV]},
               "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                           "tooltip": {"mode": "multi", "sort": "none"}}})
case = "CASE d " + " ".join(f"WHEN '{k}' THEN '{v.replace(chr(39), chr(39) * 2)}'" for k, v in LIBELLES.items()) + " ELSE d END"
panels.append(barres("Filtres les plus déclenchés",
    f"SELECT {case} AS \"filtre\", count(*) AS \"messages\" FROM decisions, unnest(detections) AS d "
    "WHERE $__timeFilter(recu_le) GROUP BY d ORDER BY 2 DESC LIMIT 12", 0, 13, 12,
    "Nombre de messages où chaque filtre (ou déclencheur direct) s'est déclenché.", "filtre"))
panels.append(barres("Échecs d'authentification",
    "SELECT 'SPF' AS \"contrôle\", count(*) FILTER (WHERE spf = 'fail') AS \"échecs\" FROM decisions WHERE $__timeFilter(recu_le) "
    "UNION ALL SELECT 'DKIM', count(*) FILTER (WHERE dkim = 'fail') FROM decisions WHERE $__timeFilter(recu_le) "
    "UNION ALL SELECT 'DMARC', count(*) FILTER (WHERE dmarc = 'fail') FROM decisions WHERE $__timeFilter(recu_le)",
    12, 13, 12, "Messages en échec SPF, DKIM ou DMARC selon Rspamd (verdicts natifs).", "contrôle"))
panels.append(tableau("Quarantaines à valider",
    "SELECT triage_id AS \"identifiant\", recu_le AS \"reçu le\", 'N' || niveau AS \"niveau\", score || '/9' AS \"score\", "
    "expediteur_affiche AS \"expéditeur affiché\", destinataire, array_to_string(detections, ', ') AS \"détections\" "
    "FROM decisions WHERE action = 'quarantaine' AND etat = 'en_attente' ORDER BY recu_le DESC LIMIT 100", 22,
    "Cliquer sur l'identifiant ouvre le message dans l'outil de quarantaine (127.0.0.1:8088).",
    ("identifiant", "http://127.0.0.1:8088/quarantaine/${__value.raw}")))
panels.append(tableau("Domaines expéditeurs à risque (N2 et plus)",
    "SELECT domaine_expediteur AS \"domaine\", count(*) AS \"messages\", 'N' || max(niveau) AS \"niveau max\", "
    "max(recu_le) AS \"dernier message\" FROM decisions WHERE $__timeFilter(recu_le) AND niveau >= 2 "
    "GROUP BY domaine_expediteur ORDER BY max(niveau) DESC, count(*) DESC LIMIT 20", 31,
    "Domaines d'expédition des messages classés N2 à N4 sur la période."))

dash = {"uid": "triage", "title": "Système de triage des emails", "tags": ["triage"], "timezone": "browser",
        "schemaVersion": 39, "version": 1, "editable": False, "refresh": "1m",
        "time": {"from": "now-7d", "to": "now"}, "panels": panels,
        "description": "Activité du filtre de triage : volumes par niveau, filtres déclenchés, quarantaines à valider."}

if __name__ == "__main__":
    sortie = Path(__file__).resolve().parent / "dashboards" / "triage.json"
    sortie.parent.mkdir(exist_ok=True)
    sortie.write_text(json.dumps(dash, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{sortie} : {len(panels)} panneaux")
