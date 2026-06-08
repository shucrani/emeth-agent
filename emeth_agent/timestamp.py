"""Primitive de date. Le hash canonique du payload est reel et deterministe.
Scellement RFC 3161 REEL : construction de la requete + POST a une TSA + parsing
du token, avec verification que le token scelle bien NOTRE hash. Sans TSA (ou si
le reseau echoue), degradation franche en 'PENDING_TSA'. On ne pretend jamais a
une date scellee qu'on n'a pas. La genTime renvoyee par la TSA est la date
autoritaire ; 'issuedAt' n'est que notre assertion de reference."""

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path

from asn1crypto import algos, cms, tsp

DEFAULT_TIMEOUT = 15
DEFAULT_CA_FILE = str(Path(__file__).resolve().parent.parent / "tsa_certs" / "freetsa_cacert.pem")


def canonical_bytes(payload):
    """Serialisation canonique (cle triees, compacte) -> bytes deterministes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(payload):
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def build_timestamp(payload, issued_at, tsa_url=None):
    """Hash reel du payload. Si tsa_url fourni, tente un scellement RFC 3161 reel ;
    sinon (ou en cas d'echec reseau), statut PENDING_TSA honnete. On ne pretend
    jamais a une date scellee qu'on n'a pas."""
    digest_hex = sha256_hex(payload)
    if not tsa_url:
        return {
            "messageImprintHash": digest_hex,
            "hashAlg": "sha256",
            "issuedAt": issued_at,
            "tsaUrl": None,
            "rfc3161Token": None,
            "status": "PENDING_TSA",
            "note": "Hash deterministe reel. Aucune TSA fournie ; sceau non effectue.",
        }
    try:
        return request_rfc3161(digest_hex, tsa_url, issued_at)
    except Exception as exc:  # reseau / TSA indisponible -> degradation franche
        return {
            "messageImprintHash": digest_hex,
            "hashAlg": "sha256",
            "issuedAt": issued_at,
            "tsaUrl": tsa_url,
            "rfc3161Token": None,
            "status": "PENDING_TSA",
            "note": f"Scellement TSA echoue ({type(exc).__name__}: {exc}). Hash reel conserve.",
        }


def _build_request(digest_bytes, nonce):
    imprint = tsp.MessageImprint({
        "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "hashed_message": digest_bytes,
    })
    req = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": imprint,
        "nonce": nonce,
        "cert_req": True,
    })
    return req.dump()


def request_rfc3161(digest_hex, tsa_url, issued_at, timeout=DEFAULT_TIMEOUT):
    """Echange RFC 3161 reel : construit la requete, POST a la TSA, parse le token.
    Verifie que le token scelle bien NOTRE hash. Retourne un timestamp SEALED."""
    digest_bytes = bytes.fromhex(digest_hex)
    nonce = int.from_bytes(os.urandom(8), "big")
    req_der = _build_request(digest_bytes, nonce)

    http_req = urllib.request.Request(
        tsa_url, data=req_der,
        headers={"Content-Type": "application/timestamp-query",
                 "Accept": "application/timestamp-reply"},
        method="POST",
    )
    with urllib.request.urlopen(http_req, timeout=timeout) as resp_http:
        resp_der = resp_http.read()

    resp = tsp.TimeStampResp.load(resp_der)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise RuntimeError(f"TSA a refuse le timestamp : statut={status}")

    token = resp["time_stamp_token"]
    tst_info = token["content"]["encap_content_info"]["content"].parse(tsp.TSTInfo)

    imprint_hash = tst_info["message_imprint"]["hashed_message"].native
    if imprint_hash.hex() != digest_hex:
        raise RuntimeError("Le token TSA ne scelle pas notre hash (imprint mismatch).")

    try:
        raw_tsa = tst_info["tsa"].native
        tsa_name = str(raw_tsa) if raw_tsa is not None else None
    except Exception:
        tsa_name = None

    return {
        "messageImprintHash": digest_hex,
        "hashAlg": "sha256",
        "issuedAt": issued_at,
        "status": "SEALED",
        "tsaUrl": tsa_url,
        "genTime": tst_info["gen_time"].native.isoformat(),
        "serialNumber": str(tst_info["serial_number"].native),
        "policyOid": tst_info["policy"].native,
        "tsaName": tsa_name,
        "imprintMatch": True,
        "rfc3161TokenB64": base64.b64encode(token.dump()).decode("ascii"),
        "note": "Sceau RFC 3161 reel. Verifiable hors-ligne (openssl ts -verify).",
    }


def verify_token(token_b64, expected_digest_hex):
    """Self-check independant (imprint) : le token scelle-t-il bien expected_digest_hex ?
    Ne verifie PAS la signature de la TSA -> voir verify_chain()."""
    token = cms.ContentInfo.load(base64.b64decode(token_b64))
    tst_info = token["content"]["encap_content_info"]["content"].parse(tsp.TSTInfo)
    return tst_info["message_imprint"]["hashed_message"].native.hex() == expected_digest_hex


def verify_chain(token_b64, digest_hex, ca_file=DEFAULT_CA_FILE,
                 openssl="openssl", timeout=20):
    """Verification cryptographique COMPLETE via `openssl ts -verify` : le token
    est-il signe par la TSA, ce certificat remonte-t-il a la racine CA (ca_file),
    et scelle-t-il bien digest_hex ? Retourne (ok, output).
    ok=True/False selon la verif ; ok=None si openssl est indisponible."""
    token_der = base64.b64decode(token_b64)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tf:
            tf.write(token_der)
            tmp = tf.name
        proc = subprocess.run(
            [openssl, "ts", "-verify", "-digest", digest_hex,
             "-in", tmp, "-token_in", "-CAfile", ca_file],
            capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return None, "openssl indisponible"
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
    output = (proc.stdout + proc.stderr).strip()
    ok = proc.returncode == 0 and "Verification: OK" in output
    return ok, output
