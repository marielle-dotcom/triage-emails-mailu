#!/bin/sh
# Système de triage, étape 5 : génère les secrets (un fichier par service, lisible
# par le seul propriétaire). Ne remplace jamais un fichier existant.
set -e
cd "$(dirname "$0")/../secrets"
umask 077
mdp() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }
[ -f .mots_de_passe ] || cat > .mots_de_passe <<FIN
DB_ADMIN=$(mdp)
DB_FILTRE=$(mdp)
DB_UI=$(mdp)
DB_LECTURE=$(mdp)
GRAFANA_ADMIN=$(mdp)
UI_SESSION=$(openssl rand -hex 32)
FIN
. ./.mots_de_passe
[ -f db.env ] || printf 'POSTGRES_ADMIN_PASSWORD=%s\nDB_FILTRE_PASSWORD=%s\nDB_UI_PASSWORD=%s\nDB_LECTURE_PASSWORD=%s\n' \
  "$DB_ADMIN" "$DB_FILTRE" "$DB_UI" "$DB_LECTURE" > db.env
[ -f filtre.env ] || printf 'TRIAGE_DB_DSN=host=triage-db dbname=triage user=triage_filtre password=%s connect_timeout=3\n' "$DB_FILTRE" > filtre.env
[ -f ui.env ] || printf 'TRIAGE_DB_DSN=host=triage-db dbname=triage user=triage_ui password=%s connect_timeout=3\nTRIAGE_UI_SECRET=%s\n' "$DB_UI" "$UI_SESSION" > ui.env
[ -f grafana.env ] || printf 'GF_SECURITY_ADMIN_PASSWORD=%s\nTRIAGE_DB_LECTURE_PASSWORD=%s\n' "$GRAFANA_ADMIN" "$DB_LECTURE" > grafana.env
ls -l
