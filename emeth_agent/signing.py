"""Signature de l'emetteur (proof). Ed25519. Repond a QUI : le document est
attribuable a Sprinkling Act (le timestamp, lui, repond a QUAND).

Le proof couvre le credential SANS son propre bloc proof (donc payload + timestamp) :
l'emetteur s'engage sur le contenu ET sur le sceau temporel.

Canonicalisation : JSON deterministe (sort_keys, compact), JCS-adjacent. Migration
vers RFC 8785 JCS + cryptosuite certifie 'eddsa-jcs-2022' = etape interop.
Cle privee de dev en clair sous keys/ (gitignore). En prod : chiffree / HSM, et la
cle publique publiee a l'URL verificationMethod."""

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .timestamp import canonical_bytes

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIV_PATH = KEYS_DIR / "issuer_ed25519_private.pem"
PUB_PATH = KEYS_DIR / "issuer_ed25519_public.pem"

VERIFICATION_METHOD = "https://sprinklingact.com/keys/issuer-ed25519#key-1"
CRYPTOSUITE = "ed25519-jsonsort-2026"  # honnete : canon JSON-sort, pas RFC 8785 JCS
CANON = "json:sort_keys,separators(',',':'),utf-8"


def ensure_issuer_key():
    """Genere la paire Ed25519 de l'emetteur si absente (dev). Retourne la cle privee."""
    if PRIV_PATH.exists():
        return load_private()
    KEYS_DIR.mkdir(exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    PRIV_PATH.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    PUB_PATH.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv


def load_private():
    return serialization.load_pem_private_key(PRIV_PATH.read_bytes(), password=None)


def load_public():
    return serialization.load_pem_public_key(PUB_PATH.read_bytes())


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_credential(signable, privkey, created):
    """signable = credential SANS proof. Retourne le bloc proof (Ed25519 deterministe)."""
    sig = privkey.sign(canonical_bytes(signable))
    return {
        "type": "DataIntegrityProof",
        "cryptosuite": CRYPTOSUITE,
        "created": created,
        "verificationMethod": VERIFICATION_METHOD,
        "proofPurpose": "assertionMethod",
        "canonicalization": CANON,
        "proofValue": "u" + _b64url(sig),  # multibase 'u' = base64url sans padding
    }


def verify_proof(credential, pubkey=None):
    """Re-canonicalise le credential sans son proof et verifie la signature emetteur."""
    if pubkey is None:
        pubkey = load_public()
    proof = credential.get("proof")
    if not proof or not str(proof.get("proofValue", "")).startswith("u"):
        return False
    signable = {k: v for k, v in credential.items() if k != "proof"}
    sig = _b64url_decode(proof["proofValue"][1:])
    try:
        pubkey.verify(sig, canonical_bytes(signable))
        return True
    except InvalidSignature:
        return False
