# Étape 3b : domaines des exemples de la section 8 du document d'architecture.
# OK = SPF autorise l'expéditeur de test 10.99.0.10 ; KO = SPF l'exclut.
cd ~/system
DKIM_P=$(openssl rsa -in triage/tests/dkim/legitime.test.lab.key -pubout -outform der 2>/dev/null | base64 -w0)
zone() {  # zone <domaine> <OK|KO> <dmarc: none|absent>
  spf="v=spf1 ip4:10.99.0.10 -all"; [ "$2" = KO ] && spf="v=spf1 ip4:203.0.113.10 -all"
  printf '\n  local-zone: "%s." static\n' "$1"
  printf '  local-data: "%s. A 10.99.0.10"\n' "$1"
  printf "  local-data: '%s. TXT \"%s\"'\n" "$1" "$spf"
  printf "  local-data: 'lab._domainkey.%s. TXT \"v=DKIM1; k=rsa; p=%s\"'\n" "$1" "$DKIM_P"
  [ "$3" = none ] && printf "  local-data: '_dmarc.%s. TXT \"v=DMARC1; p=none\"'\n" "$1"
  return 0
}
{
  echo
  echo "  # --- Étape 3b : exemples de la section 8 ---"
  zone spf-casse.test        KO none     # ex. 2 : SPF seul en échec
  zone sans-dmarc.test       KO absent   # ex. 3 : SPF + DKIM en échec, pas de DMARC
  zone 1egitime.test         OK none     # ex. 4 : typosquatting + nom affiché
  zone tout-faux.test        KO none     # ex. 5 : SPF + DKIM + DMARC en échec
  zone nouveau-service.test  OK none     # ex. 6 : domaine récent + mots-clés + lien
  zone legitime-support.test KO none     # ex. 7 : 3 échecs + typosquatting + nom affiché
  zone legitlme.test         KO none     # ex. 8 : 7 filtres
  zone anac-lab.test         OK none     # ex. 10 : dirigeant + domaine typosquatté
} >> overrides/unbound/lab-zones.conf
grep -c 'local-zone' overrides/unbound/lab-zones.conf
