# Système de triage : actions par niveau côté Dovecot (script global, exécuté pour
# chaque livraison après le script Sieve global de Mailu).
# Les en-têtes X-Risk-Level sont fiables : le filtre supprime ceux envoyés par
# l'expéditeur avant de poser les siens.
# Depuis l'étape 5, les N3/N4 ne sont plus livrés (stockage de quarantaine séparé).
require ["fileinto", "mailbox"];

# N2 (risque moyen) : dossier Suspect du destinataire.
if header :is "X-Risk-Level" "2" {
  fileinto :create "Suspect";
  stop;
}
