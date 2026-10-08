# Triage des e-mails par criticité pour Mailu

Filtre de messagerie qui analyse chaque e-mail reçu par un serveur [Mailu](https://mailu.io) 2024.06,
lui attribue un niveau de criticité de N0 à N4 et applique l'action correspondante : livraison normale,
bandeau d'avertissement, dossier Suspect ou quarantaine avec alerte à l'équipe sécurité.

Le filtre s'ajoute à Mailu par ses mécanismes d'ajustement prévus (`overrides/` et `docker-compose.yml`),
sans modifier ses images. Le domaine `anac.lab` est un domaine d'exemple de laboratoire.

## Fonctionnement

Postfix confie chaque message reçu sur le port 25 au filtre (filtre After-Queue, port 10035). Le filtre
calcule un score de 0 à 9, 1 point par contrôle en échec :

- 3 verdicts déjà calculés par Mailu (Rspamd) : SPF, DKIM, DMARC ;
- 6 filtres du triage : domaine qui imite un domaine protégé, domaine récent, mots d'urgence, liens
  masqués, pièce jointe dangereuse, nom affiché trompeur.

| Niveau | Score | Action |
| --- | --- | --- |
| N0 | 0 | Livré normalement |
| N1 | 1–2 | Livré avec un bandeau « Prudence » dans le webmail |
| N2 | 3–4 | Livré dans le dossier Suspect |
| N3 | 5–6 | Quarantaine hors de Mailu + alerte à l'équipe sécurité |
| N4 | 7–9, virus ou usurpation d'un dirigeant | Quarantaine + alerte [CRITIQUE] |

Les messages N0 à N2 sont réinjectés dans Postfix (port 10036). Les N3 et N4 sont conservés dans un
stockage séparé de Mailu et traités dans un outil web de quarantaine (libérer, confirmer, supprimer).
Chaque décision est enregistrée dans une base PostgreSQL (métadonnées uniquement, jamais le contenu)
et suivie dans un tableau de bord Grafana. Le système ne contient aucun apprentissage automatique :
règles fixes et listes modifiables.

## Contenu du dépôt

| Chemin | Contenu |
| --- | --- |
| `docker-compose.yml` | Mailu et les 4 services du triage : `triage`, `triage-db`, `triage-ui`, `triage-grafana` |
| `mailu.env.exemple` | Configuration de Mailu, sans clé secrète |
| `overrides/` | Ajustements de Mailu : Postfix (envoi au filtre, port 10036), Dovecot (dossier Suspect), Roundcube (bandeau), Rspamd et Unbound (environnement de test) |
| `triage/app/` | Code du filtre (Python, aiosmtpd) |
| `triage/referentiels/` | Listes utilisées par les filtres (YAML) |
| `triage/db/` | Image et schéma de la base des décisions (PostgreSQL 17) |
| `triage/ui/` | Outil de quarantaine (FastAPI) |
| `triage/grafana/` | Image et tableau de bord Grafana |
| `triage/tests/` | Tests unitaires et de bout en bout |
| `triage/evaluation/` | Banc de mesure sur corpus publics et résultats |
| `triage/outils/` | Génération des secrets, envoi d'un mail de test par niveau |

## Prérequis

| Élément | Exigence |
| --- | --- |
| Système | Linux 64 bits, 4 Go de mémoire au moins (ClamAV en utilise environ 2 Go), 10 Go de disque |
| Logiciels | Docker Engine avec le plugin `docker compose`, `git`, `openssl`, Python 3 avec `venv` (pour les tests) |
| Ports libres sur l'hôte | 25, 80, 443, 465, 993, 995, 4190 ; 3000 et 8088 en local |
| Réseau Docker | Le sous-réseau 192.168.203.0/24 ne doit pas être déjà utilisé |
| Accès Internet pendant l'installation | `ghcr.io` (images Mailu), Docker Hub (`redis:alpine`, `clamav/clamav-debian:1.4`, `alpine:latest`), dépôts Alpine et PyPI |

## Installation

Toutes les commandes se lancent depuis le dossier du dépôt. Celles qui touchent `data/` demandent `sudo`.

### 1. Récupérer le code

```bash
git clone https://github.com/marielle-dotcom/triage-emails-mailu.git
cd triage-emails-mailu
```

### 2. Configurer Mailu

```bash
cp mailu.env.exemple mailu.env
sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 16)/" mailu.env
chmod 600 mailu.env
```

Pour un autre domaine que `anac.lab`, modifier aussi `DOMAIN`, `HOSTNAMES` et `WEBSITE` dans `mailu.env`,
ainsi que les adresses `@anac.lab` de `docker-compose.yml` (service `triage-ui`).

### 3. Créer le certificat TLS

Certificat autosigné pour le laboratoire ; en production, utiliser un certificat d'une autorité reconnue.

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=mail.anac.lab" -addext "subjectAltName=DNS:mail.anac.lab"
chmod 600 certs/key.pem
```

### 4. Générer les secrets du triage

```bash
mkdir -p triage/secrets
sh triage/outils/generer_secrets.sh
```

Le script crée les mots de passe de la base, de l'outil de quarantaine et de Grafana dans
`triage/secrets/` (droits 600). Il ne remplace jamais un fichier existant.

### 5. Préparer les dossiers de données

Chaque conteneur écrit sous son propre utilisateur. Sans cette étape, Docker crée les dossiers au nom de
`root` : le filtre ne peut pas écrire la quarantaine et Grafana ne démarre pas.

```bash
sudo mkdir -p data/quarantaine data/triage-spool data/clamav data/grafana
sudo chown 1100:1100 data/quarantaine data/triage-spool   # filtre et outil de quarantaine
sudo chown 1000:1000 data/clamav                          # ClamAV
sudo chown 100:101 data/grafana                           # Grafana (paquet Alpine)
sudo chmod 700 data/quarantaine data/triage-spool data/grafana
```

### 6. Construire et démarrer

```bash
docker compose up -d --build
```

Le premier démarrage dure plusieurs minutes : ClamAV télécharge ses signatures avant de passer à l'état
`healthy`. Pendant ce temps, Mailu demande aux expéditeurs de réessayer plus tard, sans perte de courrier.

### 7. Créer les comptes

Le mot de passe est saisi sans s'afficher et ne reste pas dans l'historique du terminal.

```bash
read -rs MDP && docker compose exec admin flask mailu admin administrateur anac.lab "$MDP"
read -rs MDP && docker compose exec admin flask mailu admin admin anac.lab "$MDP"
read -rs MDP && docker compose exec admin flask mailu user client anac.lab "$MDP"
read -rs MDP && docker compose exec admin flask mailu user user anac.lab "$MDP"
docker compose exec admin flask mailu alias securite anac.lab administrateur@anac.lab
unset MDP
```

`administrateur@` et `admin@` sont les seuls comptes admis dans l'outil de quarantaine ; l'alias
`securite@` reçoit les alertes ; `client@` et `user@` sont les boîtes utilisées par les tests. Un compte créé en ligne de commande doit changer son mot de passe à sa
première connexion au webmail : faire cette connexion avant d'utiliser l'outil de quarantaine.

### 8. Rendre le serveur joignable depuis le poste client

Sans DNS pour `anac.lab`, ajouter cette ligne au fichier `hosts` du poste qui ouvre le webmail
(`/etc/hosts`, ou `C:\Windows\System32\drivers\etc\hosts` sous Windows), en remplaçant l'adresse :

```text
192.0.2.10   mail.anac.lab
```

## Vérifications après installation

| Contrôle | Commande ou adresse | Résultat attendu |
| --- | --- | --- |
| Services | `docker compose ps` | Tous les conteneurs `Up (healthy)`, sauf `redis` (pas de contrôle de santé) |
| Filtre branché | `docker compose exec smtp postconf -P \| grep content_filter` | `smtp/inet/content_filter = triage:[192.168.203.250]:10035` |
| Signatures antivirus | `docker compose logs antivirus \| grep daily` | `daily.cld updated` ou `up-to-date`, sans erreur |
| Webmail | `https://mail.anac.lab/webmail` | Page de connexion (avertissement de certificat attendu s'il est autosigné) |
| Outil de quarantaine | `http://127.0.0.1:8088` sur le serveur | Page de connexion, accessible avec `administrateur@anac.lab` |
| Tableau de bord | `http://127.0.0.1:3000` sur le serveur | Connexion `admin`, mot de passe `GRAFANA_ADMIN` de `triage/secrets/.mots_de_passe` |
| Bout en bout | `triage/tests/.venv/bin/python triage/outils/envoi_manuel.py` (après la section Tests) | Un mail de chaque niveau N0 à N4 envoyé à `client@anac.lab`, chacun à l'endroit annoncé |

L'outil de quarantaine et le tableau de bord n'écoutent que sur le serveur. Depuis un autre poste :
`ssh -L 8088:127.0.0.1:8088 -L 3000:127.0.0.1:3000 <compte>@<serveur>`, puis les mêmes adresses.

## Tests

Créer une fois l'environnement Python des tests :

```bash
python3 -m venv triage/tests/.venv
triage/tests/.venv/bin/pip install -r triage/tests/requirements.txt
```

| Suite | Commande | Attendu |
| --- | --- | --- |
| Tests unitaires (sans Mailu) | `triage/tests/.venv/bin/python -m pytest -q triage/tests/test_unit_etape*.py triage/tests/test_unit_scenario_a.py` | 61 réussis |
| Session de l'outil de quarantaine | commande indiquée en tête de `triage/tests/test_unit_session_ui.py` (s'exécute dans l'image de l'outil) | 6 réussis |
| Bout en bout, étapes 1 à 5 | `triage/tests/.venv/bin/python triage/tests/test_etape1.py` (puis `test_etape2.py`, `test_etape3a.py`, `test_etape3b.py`, `test_etape4.py`, `test_etape5.py`) | `OK` pour chaque suite |
| Signature DKIM intacte après le filtre | `triage/tests/.venv/bin/python triage/tests/test_dkim.py` | 3 scénarios `OK` |

Les tests de bout en bout envoient de vrais messages depuis un conteneur jetable placé sur le réseau de
test `lab-externe` (10.99.0.10), puis lisent les boîtes, la quarantaine et la base. Ils demandent les
droits Docker et laissent des messages de test dans le système. `test_etape5.py` et
`test_bandeau_webmail.py` lisent aussi les identifiants d'un compte administrateur dans un fichier
`comptes-admin-client.txt` à la racine, à créer soi-même (il est exclu du dépôt).

Banc de mesure hors ligne sur corpus publics (SpamAssassin pour les mails légitimes, corpus de phishing
de J. Nazario). Placer dans `triage/evaluation/corpus/` les dossiers `easy_ham/`, `easy_ham_2/` et
`hard_ham/` (archives SpamAssassin décompressées) et les fichiers `phishing-2023.mbox`,
`phishing-2024.mbox` et `phishing-2025.mbox` (fichiers Nazario `phishing-<année>` renommés), puis :

```bash
EVAL_NATIFS=origine EVAL_TRANSPOSITION=0 triage/tests/.venv/bin/python triage/evaluation/evaluer.py <nom>
```

Résultat sur le jeu de test (2 059 mails légitimes, 155 phishing de 2025) : 0 % des mails légitimes en
N2 ou plus, 72,9 % du phishing signalé (N1 ou plus), dont 7,1 % en N2 ou plus ; médiane de 5 ms par
message, aucune erreur. Le corpus Nazario de l'année en cours s'enrichit au fil du temps : une version
plus récente peut donner des chiffres légèrement différents.

## Environnement de laboratoire

Le dépôt inclut un environnement de test qui n'est pas nécessaire en production :

- le réseau interne `lab-externe` (10.99.0.0/24) et l'adresse 10.99.0.2 de `front`, d'où partent les
  tests de bout en bout comme depuis Internet ;
- les zones DNS de domaines de test (`overrides/unbound/lab-zones.conf`) avec leurs enregistrements SPF,
  DKIM et DMARC, et la clé privée `triage/tests/dkim/legitime.test.lab.key`, qui ne sert qu'à signer les
  mails de test du domaine fictif `legitime.test` ;
- l'exemption de greylisting pour ces expéditeurs (`overrides/rspamd/greylist.conf`).

En production, retirer ces éléments : le filtre fonctionne sans eux.

## Ce qui n'est pas dans le dépôt

Les secrets (`mailu.env`, `triage/secrets/`), le certificat et sa clé (`certs/`), les données
d'exécution (`data/`) et les corpus d'évaluation. Les étapes 2 à 5 de l'installation les recréent ;
les corpus se téléchargent depuis
[SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
(`20030228_easy_ham`, `easy_ham_2`, `hard_ham`) et le
[corpus de phishing de J. Nazario](https://monkey.org/~jose/phishing/) (`phishing-2023`, `2024`, `2025`).
