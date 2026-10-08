#!/bin/sh
# Initialise la base au premier démarrage (schéma + comptes), puis lance PostgreSQL.
set -e
PGDATA=/var/lib/postgresql/data
mkdir -p "$PGDATA" /run/postgresql
chown -R postgres:postgres "$PGDATA" /run/postgresql
chmod 700 "$PGDATA"

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "Initialisation de la base de triage"
  printf '%s\n' "$POSTGRES_ADMIN_PASSWORD" > /tmp/pw
  chown postgres /tmp/pw
  su-exec postgres initdb -D "$PGDATA" -U postgres --pwfile=/tmp/pw -E UTF8 --no-locale \
    --auth-local=peer --auth-host=scram-sha-256 >/dev/null
  rm -f /tmp/pw
  cat >> "$PGDATA/postgresql.conf" <<CONF
listen_addresses = '*'
password_encryption = scram-sha-256
log_timezone = 'Europe/Paris'
timezone = 'Europe/Paris'
CONF
  # Connexions réseau : uniquement depuis le réseau Docker de Mailu, base « triage ».
  echo "host triage triage_filtre,triage_ui,triage_lecture 192.168.203.0/24 scram-sha-256" >> "$PGDATA/pg_hba.conf"
  su-exec postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w start >/dev/null
  su-exec postgres psql -q -v ON_ERROR_STOP=1 \
    -v filtre_pw="$DB_FILTRE_PASSWORD" -v ui_pw="$DB_UI_PASSWORD" -v lecture_pw="$DB_LECTURE_PASSWORD" \
    -f /init/schema.sql
  su-exec postgres pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null
fi

exec su-exec postgres postgres -D "$PGDATA"
