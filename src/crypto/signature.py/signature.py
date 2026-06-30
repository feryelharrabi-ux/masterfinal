"""
crypto/signature.py

Signature des racines de Merkle (root_b) avec Ed25519.

Message signe
--------------
signature_b = Sign(sk, root_b || batchId || sourceId || startSeq || endSeq || timestamp)

On construit ce message de maniere canonique (meme principe de separateur
explicite que dans hash_chain.py) avant de le signer, pour eviter toute
ambiguite de concatenation.

Verification
-------------
Verify(pk, signature_b, message_b) -> True / False

Ed25519 est utilise via la librairie `cryptography` (deterministe, pas de
nonce a gerer manuellement, tailles de cle/signature fixes : 32 octets cle
publique, 64 octets signature).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

FIELD_SEPARATOR = b"\x1f"  # meme convention que hash_chain.py


def _to_bytes(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


@dataclass
class BatchSignaturePayload:
    """Champs necessaires pour construire le message signe d'un batch."""
    root_hex: str
    batch_id: str
    source_id: str
    start_seq: int
    end_seq: int
    timestamp: str

    def to_message_bytes(self) -> bytes:
        """message_b = root_b || batchId || sourceId || startSeq || endSeq || timestamp
        (avec separateurs explicites entre champs)."""
        fields = [
            _to_bytes(self.root_hex),
            _to_bytes(self.batch_id),
            _to_bytes(self.source_id),
            _to_bytes(self.start_seq),
            _to_bytes(self.end_seq),
            _to_bytes(self.timestamp),
        ]
        return FIELD_SEPARATOR.join(fields)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Genere une nouvelle paire de cles Ed25519 (sk, pk)."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk


def private_key_to_bytes(sk: Ed25519PrivateKey) -> bytes:
    """Serialise la cle privee en bytes bruts (32 octets), format Raw."""
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_from_bytes(data: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(data)


def public_key_to_bytes(pk: Ed25519PublicKey) -> bytes:
    """Serialise la cle publique en bytes bruts (32 octets), format Raw."""
    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)


def sign_batch(sk: Ed25519PrivateKey, payload: BatchSignaturePayload) -> bytes:
    """signature_b = Sign(sk, message_b)

    Retourne la signature brute (64 octets pour Ed25519).
    """
    message = payload.to_message_bytes()
    return sk.sign(message)


def verify_batch_signature(pk: Ed25519PublicKey, signature: bytes, payload: BatchSignaturePayload) -> bool:
    """Verify(pk, signature_b, message_b) -> True/False

    Ne leve jamais d'exception : retourne False en cas de signature
    invalide ou de message incorrect.
    """
    message = payload.to_message_bytes()
    try:
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Toute autre erreur (mauvais type, cle corrompue, etc.) est traitee
        # comme une verification echouee plutot que de propager l'exception.
        return False
