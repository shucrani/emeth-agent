"""Signature de l'emetteur (proof). Repond a QUI : le document est attribuable a
Sprinkling Act (le timestamp, lui, repond a QUAND).

Cryptosuite : eddsa-jcs-2022 (W3C Data Integrity EdDSA). Construction conforme :
  hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document_sans_proof))
  proofValue = multibase base58btc ('z') de Ed25519.sign(hashData)
JCS = RFC 8785 (via canonical_bytes). Auto-coherent et teste en round-trip ;
PAS encore cross-verifie contre un verifieur Data Integrity tiers.

Cle : EMETH_ISSUER_KEY (chemin PEM, +EMETH_ISSUER_KEY_PASSWORD) en production ;
sinon cle de dev auto-generee en clair sous keys/ (gitignore). En prod : HSM/chiffree
et cle publique publiee a l'URL verificationMethod."""

import hashlib
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .timestamp import canonical_bytes

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIV_PATH = KEYS_DIR / "issuer_ed25519_private.pem"
PUB_PATH = KEYS_DIR / "issuer_ed25519_public.pem"

VERIFICATION_METHOD = "https://sprinklingact.com/keys/issuer-ed25519#key-1"
CRYPTOSUITE = "eddsa-jcs-2022"

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def _b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


# --- gestion des cles ---

def ensure_issuer_key():
    """Genere la paire Ed25519 de dev si absente. Retourne la cle privee."""
    if PRIV_PATH.exists():
        return serialization.load_pem_private_key(PRIV_PATH.read_bytes(), password=None)
    KEYS_DIR.mkdir(exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    PRIV_PATH.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    PUB_PATH.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv


def load_issuer_key():
    """Cle de production via EMETH_ISSUER_KEY (PEM, +EMETH_ISSUER_KEY_PASSWORD) ;
    sinon cle de dev (avec avertissement)."""
    env_path = os.environ.get("EMETH_ISSUER_KEY")
    if env_path:
        pwd = os.environ.get("EMETH_ISSUER_KEY_PASSWORD")
        return serialization.load_pem_private_key(
            Path(env_path).read_bytes(),
            password=pwd.encode() if pwd else None)
    print("emeth: ATTENTION cle emetteur de DEV auto-generee "
          "(definir EMETH_ISSUER_KEY pour la production)", file=sys.stderr)
    return ensure_issuer_key()


def load_public():
    """Cle publique miroir de load_issuer_key (prod via env, sinon dev)."""
    env_path = os.environ.get("EMETH_ISSUER_KEY")
    if env_path:
        pwd = os.environ.get("EMETH_ISSUER_KEY_PASSWORD")
        priv = serialization.load_pem_private_key(
            Path(env_path).read_bytes(),
            password=pwd.encode() if pwd else None)
        return priv.public_key()
    return serialization.load_pem_public_key(PUB_PATH.read_bytes())


# --- eddsa-jcs-2022 ---

def _proof_config(created, context):
    return {
        "@context": context,
        "type": "DataIntegrityProof",
        "cryptosuite": CRYPTOSUITE,
        "created": created,
        "verificationMethod": VERIFICATION_METHOD,
        "proofPurpose": "assertionMethod",
    }


def _hash_data(document_without_proof, proof_config):
    pc_hash = hashlib.sha256(canonical_bytes(proof_config)).digest()
    doc_hash = hashlib.sha256(canonical_bytes(document_without_proof)).digest()
    return pc_hash + doc_hash


def sign_credential(document, privkey, created):
    """document = credential SANS proof (avec @context + timestamp). Retourne le bloc proof."""
    context = document.get("@context", ["https://www.w3.org/ns/credentials/v2"])
    pc = _proof_config(created, context)
    signature = privkey.sign(_hash_data(document, pc))
    proof = dict(pc)
    proof["proofValue"] = "z" + _b58encode(signature)
    return proof


def verify_proof(credential, pubkey=None):
    """Reconstruit hashData (proofConfig + document sans proof) et verifie la signature."""
    if pubkey is None:
        pubkey = load_public()
    proof = credential.get("proof")
    if not proof or not str(proof.get("proofValue", "")).startswith("z"):
        return False
    document = {k: v for k, v in credential.items() if k != "proof"}
    pc = {k: v for k, v in proof.items() if k != "proofValue"}
    try:
        pubkey.verify(_b58decode(proof["proofValue"][1:]), _hash_data(document, pc))
        return True
    except InvalidSignature:
        return False
