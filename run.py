"""Produit UN document-frontiere pour une fixture et l'ecrit dans out/.

Usage : python run.py [fixtures/acme_test.json]
"""

import json
import os
import sys
from pathlib import Path

from emeth_agent.generate import generate, write_document
from emeth_agent.signing import verify_proof
from emeth_agent.timestamp import verify_chain

ISSUED_AT = "2026-06-08T19:30:00Z"  # date d'emission de reference (notre assertion)
# TSA RFC 3161 par defaut. Override : BOUNDARY_TSA_URL=...  ou  --no-seal
DEFAULT_TSA = "https://freetsa.org/tsr"


def main(fixture_path, tsa_url=DEFAULT_TSA):
    with open(fixture_path, encoding="utf-8") as fh:
        fixture = json.load(fh)

    cred = generate(fixture["subject"], fixture["declared_inputs"], ISSUED_AT, tsa_url=tsa_url)
    path = write_document(cred)

    subj = cred["credentialSubject"]
    ts = cred["timestamp"]
    print(f"Document-frontiere produit : {path}")
    print(f"  Sujet  : {subj['name']} ({subj.get('identifier')})")
    print(f"  Classe : {subj['class']}")
    print("  Positions :")
    for p in subj["positions"]:
        print(f"    - {p['provision']:<18} {p['scopeStatus']:<13} ({p['gate']})")
    print(f"  Hash   : {ts['messageImprintHash'][:16]}...  [{ts['status']}]")
    if ts["status"] == "SEALED":
        print(f"  Sceau  : genTime={ts['genTime']}  serial={ts['serialNumber']}")
        print(f"           TSA={ts['tsaUrl']}  policy={ts['policyOid']}")
        ok, _out = verify_chain(ts["rfc3161TokenB64"], ts["messageImprintHash"])
        verdict = {True: "OK (signe par la TSA, remonte a la racine CA freetsa)",
                   False: "ECHEC", None: "openssl indisponible (verif chaine sautee)"}[ok]
        print(f"  Chaine : {verdict}")
    else:
        print(f"           {ts.get('note', '')}")
    proof_ok = verify_proof(cred)
    print(f"  Proof  : {'OK (signe Ed25519 par l-emetteur Sprinkling Act)' if proof_ok else 'INVALIDE'}")
    print(f"  termsOfUse.doesNotAssert : {len(cred['termsOfUse']['doesNotAssert'])} refus graves")
    return cred


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--no-seal"]
    tsa = None if "--no-seal" in sys.argv else os.environ.get("BOUNDARY_TSA_URL", DEFAULT_TSA)
    fx = args[0] if args else str(Path(__file__).parent / "fixtures" / "acme_test.json")
    main(fx, tsa_url=tsa)
