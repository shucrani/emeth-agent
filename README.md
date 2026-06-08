# Emeth Agent

Generates signed, timestamped boundary-attestation documents for the EU AI Act. Rule-based, no LLM.

Emeth states one narrow thing about an AI system and makes it independently checkable: this system sits at this regulatory boundary, in this class, on this date. It signs that statement and timestamps it. It does not tell you whether you are compliant, and it is not legal advice. No tool can certify compliance, and Emeth does not pretend to.

The name is Hebrew for "truth" (אמת). In the Golem legend, *emeth* on the forehead animates the figure; erase the first letter and *meth* (מת, "dead") remains. An agent that states only what it can verify, and stops at the edge.

## What it does

- Takes a subject's self-declared facts plus the current regulatory corpus.
- Classifies the subject's position against named AI Act gates (Art. 50 transparency, Art. 51 GPAI, Annex III) as `IN_SCOPE` or `UNDETERMINED`. Never as a compliance verdict.
- Emits a [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/), signed Ed25519 by the issuer and timestamped via RFC 3161.

## What it does not do

It does not assert compliance, give legal advice, interpret the law, or check whether the subject's declarations are true. Declared facts are recorded, not verified (a notary model). Interpretive questions, such as the Art. 6(3) high-risk derogation, are flagged for a qualified lawyer and never decided by the tool. The refusal is enforced in the data model, not just in prose: there is no `compliant` field to emit, and a test fails if a verdict token ever leaks into the output.

## Install

```
pip install -e .
```

Python 3.11+. Two dependencies: `cryptography` and `asn1crypto`.

## Usage

```
python run.py fixtures/hrtech_deployer.json
```

A Belgian HR-screening deployer running emotion recognition on candidates produces:

```
Classe : IN_SCOPE:2 / UNDETERMINED:0
  Annexe III   IN_SCOPE   (... evaluation Art. 6(3) requise, PAS haut-risque automatique)
  Art. 50(3)   IN_SCOPE   (... reconnaissance d'emotions / categorisation biometrique)
  Proof  : OK (signe Ed25519 par l-emetteur Sprinkling Act)
```

Gate labels are in French; the corpus is EU regulation, maintained in French. The full JSON credential is written to `out/`.

## How verification works

You do not have to trust me. Each document carries two independent proofs.

Issuer signature (Ed25519): the credential is signed with the issuer key over its canonical bytes. Recompute and verify against the public key; tamper with any field and the signature fails.

Timestamp (RFC 3161): the document hash is sealed by a Time-Stamp Authority, and the token verifies against the TSA root.

```
openssl ts -verify -digest <hash> -in token.der -token_in -CAfile tsa_certs/freetsa_cacert.pem
```

Backdate the document and the timestamp fails. `run.py` prints `Proof : OK` and `Chaine : OK` only after performing both checks.

## How it decides

A small corpus of regulatory gates (`corpus/eu_ai_act.json`), each an individually versioned object with a deterministic scope rule, and a three-valued (Kleene) classifier. Same input, same corpus, same output, on any machine. Rules, not a model, on purpose: an attestation you cannot reproduce byte for byte is not worth signing, and published benchmarks put legal-AI hallucination between 17% and 33%. Emeth cannot hallucinate a gate it does not have.

## Scope, limitations, honesty

- Not legal advice. States position, not compliance.
- The corpus is fact-checked against the regulation text but not legally certified. Scope rules that embed interpretation are flagged for a lawyer, not asserted.
- Several effective dates are provisional (Digital Omnibus, not yet in the Official Journal) and marked as such in the corpus.
- The bundled issuer key and the freetsa timestamp root are development defaults. Production needs a secured issuer key published at the `verificationMethod` URL, and an authoritative Time-Stamp Authority.

## Tests

```
python -m pytest          # or: python -m unittest discover -s tests
```

Covers classification (including the horizon refusal), RFC 3161 sealing and chain verification, and signature round-trips.

## License

Apache-2.0. See [LICENSE](LICENSE).

Built in Brussels by Lamar B. Shucrani.
