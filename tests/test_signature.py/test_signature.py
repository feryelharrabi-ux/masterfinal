"""Tests unitaires pour crypto/signature.py"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.signature import (
    BatchSignaturePayload,
    generate_keypair,
    sign_batch,
    verify_batch_signature,
    private_key_to_bytes,
    private_key_from_bytes,
    public_key_to_bytes,
    public_key_from_bytes,
)


def make_payload(root_hex="a" * 64):
    return BatchSignaturePayload(
        root_hex=root_hex,
        batch_id="2005-06-03T15:42:00Z|dt1m",
        source_id="node-1",
        start_seq=100,
        end_seq=199,
        timestamp="2005-06-03T15:43:00Z",
    )


class TestKeyGeneration(unittest.TestCase):
    def test_generate_keypair_returns_keys(self):
        sk, pk = generate_keypair()
        self.assertIsNotNone(sk)
        self.assertIsNotNone(pk)

    def test_key_serialization_roundtrip(self):
        sk, pk = generate_keypair()
        sk_bytes = private_key_to_bytes(sk)
        pk_bytes = public_key_to_bytes(pk)

        self.assertEqual(len(sk_bytes), 32)
        self.assertEqual(len(pk_bytes), 32)

        sk2 = private_key_from_bytes(sk_bytes)
        pk2 = public_key_from_bytes(pk_bytes)

        # La cle reconstruite doit produire la meme signature/verification
        payload = make_payload()
        sig = sign_batch(sk2, payload)
        self.assertTrue(verify_batch_signature(pk2, sig, payload))


class TestSignAndVerify(unittest.TestCase):
    def test_valid_signature_verifies(self):
        sk, pk = generate_keypair()
        payload = make_payload()
        sig = sign_batch(sk, payload)
        self.assertTrue(verify_batch_signature(pk, sig, payload))

    def test_signature_length_is_64_bytes(self):
        sk, pk = generate_keypair()
        sig = sign_batch(sk, make_payload())
        self.assertEqual(len(sig), 64)

    def test_tampered_root_fails_verification(self):
        sk, pk = generate_keypair()
        payload = make_payload(root_hex="a" * 64)
        sig = sign_batch(sk, payload)

        tampered_payload = make_payload(root_hex="b" * 64)
        self.assertFalse(verify_batch_signature(pk, sig, tampered_payload))

    def test_tampered_batch_id_fails_verification(self):
        sk, pk = generate_keypair()
        payload = make_payload()
        sig = sign_batch(sk, payload)

        tampered = BatchSignaturePayload(
            root_hex=payload.root_hex,
            batch_id="TAMPERED-BATCH-ID",
            source_id=payload.source_id,
            start_seq=payload.start_seq,
            end_seq=payload.end_seq,
            timestamp=payload.timestamp,
        )
        self.assertFalse(verify_batch_signature(pk, sig, tampered))

    def test_wrong_public_key_fails_verification(self):
        sk, pk = generate_keypair()
        _, other_pk = generate_keypair()
        payload = make_payload()
        sig = sign_batch(sk, payload)
        self.assertFalse(verify_batch_signature(other_pk, sig, payload))

    def test_corrupted_signature_bytes_fail_verification(self):
        sk, pk = generate_keypair()
        payload = make_payload()
        sig = sign_batch(sk, payload)

        corrupted = bytes([sig[0] ^ 0xFF]) + sig[1:]
        self.assertFalse(verify_batch_signature(pk, corrupted, payload))

    def test_signature_is_deterministic_for_same_inputs(self):
        # Ed25519 est deterministe (pas de nonce aleatoire comme ECDSA)
        sk, pk = generate_keypair()
        payload = make_payload()
        sig1 = sign_batch(sk, payload)
        sig2 = sign_batch(sk, payload)
        self.assertEqual(sig1, sig2)

    def test_message_bytes_changes_with_each_field(self):
        base = make_payload()
        variants = [
            BatchSignaturePayload(base.root_hex, "OTHER", base.source_id, base.start_seq, base.end_seq, base.timestamp),
            BatchSignaturePayload(base.root_hex, base.batch_id, "OTHER", base.start_seq, base.end_seq, base.timestamp),
            BatchSignaturePayload(base.root_hex, base.batch_id, base.source_id, 999, base.end_seq, base.timestamp),
            BatchSignaturePayload(base.root_hex, base.batch_id, base.source_id, base.start_seq, 999, base.timestamp),
            BatchSignaturePayload(base.root_hex, base.batch_id, base.source_id, base.start_seq, base.end_seq, "OTHER"),
        ]
        base_msg = base.to_message_bytes()
        for v in variants:
            self.assertNotEqual(v.to_message_bytes(), base_msg)


if __name__ == "__main__":
    unittest.main()
