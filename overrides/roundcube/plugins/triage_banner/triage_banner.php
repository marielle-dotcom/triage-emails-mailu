<?php

/**
 * Système de triage, étape 4 : bandeau « Prudence » au-dessus des messages N1.
 *
 * Le filtre de triage pose X-Warning-Banner: true sur les messages de niveau N1
 * (et supprime tout exemplaire envoyé par l'expéditeur). Ce plugin demande à
 * Roundcube de lire cet en-tête et affiche un avertissement au-dessus du message,
 * sans modifier le message lui-même.
 */
class triage_banner extends rcube_plugin
{
    public $task = 'mail';

    // Noms des détections (X-Detection-Type) traduits pour l'utilisateur.
    private $libelles = [
        'spf'                   => "l'expéditeur n'est pas autorisé par son domaine (SPF)",
        'dkim'                  => 'signature du message invalide (DKIM)',
        'dmarc'                 => "politique d'authentification du domaine non respectée (DMARC)",
        'typosquatting'         => "domaine d'expédition qui imite un domaine connu",
        'recent_domain'         => "domaine d'expédition créé très récemment",
        'urgency_keywords'      => "formulations pressantes typiques de l'hameçonnage",
        'masked_links'          => 'liens raccourcis ou trompeurs',
        'suspicious_attachment' => 'pièce jointe potentiellement dangereuse',
        'display_name_mismatch' => "nom affiché incohérent avec l'adresse réelle",
    ];

    function init()
    {
        $this->add_hook('storage_init', [$this, 'storage_init']);
        $this->add_hook('message_objects', [$this, 'message_objects']);
    }

    /**
     * Ajoute les en-têtes de triage à ceux que Roundcube récupère sur le serveur IMAP.
     */
    function storage_init($p)
    {
        $p['fetch_headers'] = trim(($p['fetch_headers'] ?? '') . ' X-WARNING-BANNER X-RISK-LEVEL X-DETECTION-TYPE');
        return $p;
    }

    /**
     * Ajoute le bandeau dans la zone des avertissements, au-dessus du message.
     */
    function message_objects($p)
    {
        $headers = $p['message']->headers ?? null;
        if (!$headers || strtolower(trim((string) $headers->get('x-warning-banner'))) !== 'true') {
            return $p;
        }

        $raisons = [];
        foreach (explode(',', (string) $headers->get('x-detection-type')) as $code) {
            $code = trim($code);
            if ($code !== '' && $code !== 'none') {
                $raisons[] = $this->libelles[$code] ?? $code;
            }
        }

        $texte = html::tag('strong', null, 'Prudence :') . ' '
            . rcube::Q("ce message présente des signes de risque. Vérifiez l'expéditeur avant de cliquer sur un lien, "
                . "d'ouvrir une pièce jointe ou de répondre à une demande (paiement, identifiants).");
        if ($raisons) {
            $texte .= html::div(['style' => 'margin-top:.3em'], rcube::Q('Motif : ' . implode(' ; ', $raisons) . '.'));
        }

        $p['content'][] = html::div([
            'id'    => 'triage-warning-banner',
            'class' => 'notice',
            'style' => 'background:#fff3cd;border:1px solid #e0a800;border-left:6px solid #e0a800;'
                     . 'color:#5c4400;padding:.6em .9em;margin:.4em 0;border-radius:4px',
        ], $texte);

        return $p;
    }
}
