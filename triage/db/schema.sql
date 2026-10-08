-- Système de triage, étape 5 : base des décisions (document d'architecture, §7).
-- Métadonnées uniquement : ni corps, ni objet, ni pièces jointes.

CREATE ROLE triage_filtre  LOGIN PASSWORD :'filtre_pw';   -- le filtre : ajoute des décisions
CREATE ROLE triage_ui      LOGIN PASSWORD :'ui_pw';       -- l'outil de quarantaine : valide, libère, supprime
CREATE ROLE triage_lecture LOGIN PASSWORD :'lecture_pw';  -- Grafana : lecture seule

CREATE DATABASE triage;
\connect triage
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO triage_filtre, triage_ui, triage_lecture;

CREATE TABLE decisions (
    id                   bigserial PRIMARY KEY,
    triage_id            text        NOT NULL UNIQUE,
    recu_le              timestamptz NOT NULL DEFAULT now(),
    message_id           text,
    expediteur_affiche   text,       -- en-tête From
    domaine_expediteur   text,
    enveloppe_expediteur text,       -- MAIL FROM
    destinataire         text        NOT NULL,
    spf                  text,
    dkim                 text,
    dmarc                text,
    spam_bar             text,       -- score Rspamd, pour information
    score                smallint    NOT NULL CHECK (score BETWEEN 0 AND 9),
    niveau               smallint    NOT NULL CHECK (niveau BETWEEN 0 AND 4),
    detections           text[]      NOT NULL DEFAULT '{}',
    raisons              jsonb       NOT NULL DEFAULT '{}',
    declencheur_direct   text,
    action               text        NOT NULL CHECK (action IN ('livre', 'suspect', 'quarantaine')),
    etat                 text        NOT NULL DEFAULT 'sans_objet'
                         CHECK (etat IN ('sans_objet', 'en_attente', 'confirme', 'libere', 'supprime', 'expire')),
    fichier_sha256       text,       -- empreinte du message en quarantaine
    taille               integer,
    valide_par           text,
    valide_le            timestamptz
);
CREATE INDEX decisions_recu_le ON decisions (recu_le);
CREATE INDEX decisions_etat ON decisions (etat) WHERE action = 'quarantaine';

-- Validation documentée : chaque action humaine ou automatique sur une quarantaine.
CREATE TABLE journal_validation (
    id          bigserial   PRIMARY KEY,
    triage_id   text        NOT NULL REFERENCES decisions (triage_id) ON DELETE CASCADE,
    horodatage  timestamptz NOT NULL DEFAULT now(),
    utilisateur text        NOT NULL,
    action      text        NOT NULL,
    etat_avant  text,
    etat_apres  text,
    commentaire text
);

GRANT INSERT ON decisions TO triage_filtre;
-- Lecture de la seule colonne triage_id : nécessaire à ON CONFLICT (rejeu sans doublon).
GRANT SELECT (triage_id) ON decisions TO triage_filtre;
GRANT USAGE ON SEQUENCE decisions_id_seq TO triage_filtre;

GRANT SELECT, DELETE ON decisions TO triage_ui;
GRANT UPDATE (etat, valide_par, valide_le) ON decisions TO triage_ui;
GRANT SELECT, INSERT ON journal_validation TO triage_ui;
GRANT USAGE ON SEQUENCE journal_validation_id_seq TO triage_ui;

GRANT SELECT ON decisions, journal_validation TO triage_lecture;
