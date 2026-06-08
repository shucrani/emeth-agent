"""Assemblage du document-frontiere comme W3C Verifiable Credential 2.0
(attestation non-assurance). Le hash + le timestamp portent sur le payload
SANS proof ni timestamp (sinon dependance circulaire)."""

import json
from pathlib import Path

from . import __version__
from .classify import classify
from .corpus import load_corpus
from .signing import ensure_issuer_key, sign_credential
from .terms import terms_of_use
from .timestamp import build_timestamp

OUT_DIR = Path(__file__).resolve().parent.parent / "out"

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
SCHEMA_URL = "https://sprinklingact.com/schemas/boundary-attestation/v0.2"


def _ulid_like(subject_name, issued_at):
    """Identifiant deterministe et lisible pour t0 (un vrai ULID viendra en prod)."""
    base = subject_name.lower().replace(" ", "-")
    return f"ba-{base}-{issued_at.replace(':', '').replace('-', '')}"


def generate(subject, declared_inputs, issued_at, filter_name="EU_AI_ACT", tsa_url=None):
    corpus = load_corpus(filter_name)
    positions, class_label = classify(corpus, declared_inputs)

    doc_id = _ulid_like(subject["name"], issued_at)

    declared = [
        {"key": k, "value": v, "declaredBy": "subject",
         "declaredAt": issued_at, "verified": False}        # modele notaire
        for k, v in declared_inputs.items()
    ]

    sources = []
    seen = set()
    for p in positions:
        s = p["gateSource"]
        if s["url"] not in seen:
            seen.add(s["url"])
            sources.append(s)

    # payload signe/horodate : tout sauf proof + timestamp
    payload = {
        "@context": [VC_CONTEXT],
        "type": ["VerifiableCredential", "BoundaryAttestationCredential"],
        "id": f"urn:boundary:{doc_id}",
        "issuer": {
            "id": "https://sprinklingact.com",
            "name": "Sprinkling Act",
            "identifier": "BE 1034.962.482",
        },
        "validFrom": issued_at,
        "credentialSchema": {"type": "JsonSchema", "id": SCHEMA_URL},
        "credentialSubject": {
            "name": subject["name"],
            "identifier": subject.get("identifier"),
            "jurisdiction": subject.get("jurisdiction"),
            "responsibleParty": "subject",
            "declaredInputs": declared,
            "positions": positions,
            "class": class_label,
        },
        "termsOfUse": terms_of_use(),
        "evidence": [{
            "type": "DeclaredInputEvidence",
            "note": "Intrants enregistres tels que declares par le sujet, NON verifies "
                    "par l'emetteur (ISRS 4400 / modele notaire).",
        }],
        "corpusSnapshot": {"snapshotId": corpus["snapshot_id"],
                           "snapshotDate": corpus["snapshot_date"]},
        "sources": sources,
        "generatorVersion": __version__,
    }

    credential = dict(payload)
    credential["timestamp"] = build_timestamp(payload, issued_at, tsa_url=tsa_url)
    # proof = signature emetteur sur (payload + timestamp). Ed25519, cle de dev auto-generee.
    credential["proof"] = sign_credential(credential, ensure_issuer_key(), issued_at)
    return credential


def write_document(credential):
    OUT_DIR.mkdir(exist_ok=True)
    doc_id = credential["id"].split(":")[-1]
    path = OUT_DIR / f"{doc_id}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(credential, fh, ensure_ascii=False, indent=2)
    return path
