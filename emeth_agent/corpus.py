"""Chargement du corpus reglementaire. Chaque porte (gate) = un objet versionne
(modele 'obligation = objet individuel'). Une mutation re-score seulement les
positions affectees."""

import json
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"


def load_corpus(filter_name="EU_AI_ACT"):
    """Retourne le snapshot du corpus pour un filtre donne."""
    path = CORPUS_DIR / f"{filter_name.lower()}.json"
    if not path.exists():
        raise FileNotFoundError(f"Corpus introuvable : {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def snapshot_ref(corpus):
    return {
        "snapshotId": corpus["snapshot_id"],
        "snapshotDate": corpus["snapshot_date"],
    }
