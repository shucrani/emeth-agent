"""termsOfUse = la delimitation, machine-readable. 6 clauses forcees par les
disclaimers reels des concurrents (Vanta EULA, Drata terms) + ISRS 4400 (AUP).

Constante : ce bloc est identique sur chaque document. C'est l'horizon grave."""

TERMS_OF_USE = {
    "type": "BoundaryAttestationPolicy",
    "asserts": [
        "existence du sujet",
        "position du sujet vis-a-vis de portes reglementaires nommees",
        "classe (reformulation mecanique des positions)",
        "date + horodatage cryptographique",
    ],
    "doesNotAssert": [
        "conformite ou non-conformite",
        "avis juridique ou interpretation",
        "verite des intrants declares par le sujet",
        "garantie de resultat, certification ou audit",
        "obligation d'agir",
        "aptitude a un quelconque usage",
    ],
    "clauses": [
        "Cette attestation ne constitue pas un avis juridique ni un avis de conformite.",
        "Elle ne garantit aucun resultat de conformite, certification, ou resultat d'audit.",
        "Elle enregistre des faits declares par le sujet ; le sujet est seul responsable "
        "de la determination de sa situation et de la verite de ses declarations.",
        "Fournie 'EN L'ETAT', sans garantie d'exactitude sur tout champ derive ; "
        "a valider avant tout recours.",
        "Responsabilite de l'emetteur plafonnee aux frais percus sur les 12 mois precedents.",
        "Les classes sont produites par un processus deterministe, trace a la regle et "
        "lie au texte reglementaire cite (aucune generation par modele de langage).",
    ],
}


def terms_of_use():
    return TERMS_OF_USE
