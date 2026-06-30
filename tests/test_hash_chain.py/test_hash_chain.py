"""Tests unitaires pour crypto/hash_chain.py"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.hash_chain import (
    LogRecord,
    build_chain,
    verify_chain,
    find_break_point,
    canonical_log_bytes,
    leaf_hash,
    chain_hash,
    GENESIS_CHAIN,
)


def make_records(n=5):
    return [
        LogRecord(
            source_id=f"node-{i % 3}",
            seq_no=i,
            timestamp=f"2005-06-03T15:42:{i:02d}Z",
            event_id=f"evt-{i}",
            event_template="something happened",
            raw_log=f"raw content of log {i}",
        )
        for i in range(n)
    ]


class TestCanonicalSerialization(unittest.TestCase):
    def test_canonical_is_deterministic(self):
        record = make_records(1)[0]
        b1 = canonical_log_bytes(record, GENESIS_CHAIN.hex())
        b2 = canonical_log_bytes(record, GENESIS_CHAIN.hex())
        self.assertEqual(b1, b2)

    def test_canonical_changes_with_previous_hash(self):
        record = make_records(1)[0]
        b1 = canonical_log_bytes(record, GENESIS_CHAIN.hex())
        b2 = canonical_log_bytes(record, "ff" * 32)
        self.assertNotEqual(b1, b2)

    def test_field_separator_prevents_ambiguous_concat(self):
        # source_id="1", seq_no=23  vs  source_id="12", seq_no=3
        # Sans separateur, la concatenation naive donnerait "123" dans les
        # deux cas. Avec separateur, les bytes resultants different.
        r1 = LogRecord("1", 23, "t", "e", "tpl", "raw")
        r2 = LogRecord("12", 3, "t", "e", "tpl", "raw")
        b1 = canonical_log_bytes(r1, GENESIS_CHAIN.hex())
        b2 = canonical_log_bytes(r2, GENESIS_CHAIN.hex())
        self.assertNotEqual(b1, b2)


class TestLeafAndChainHash(unittest.TestCase):
    def test_leaf_hash_deterministic(self):
        record = make_records(1)[0]
        h1 = leaf_hash(record, GENESIS_CHAIN.hex())
        h2 = leaf_hash(record, GENESIS_CHAIN.hex())
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 32)  # SHA-256 -> 32 octets

    def test_chain_hash_depends_on_previous(self):
        leaf = b"\x01" * 32
        c1 = chain_hash(GENESIS_CHAIN, leaf)
        c2 = chain_hash(b"\x02" * 32, leaf)
        self.assertNotEqual(c1, c2)


class TestBuildAndVerifyChain(unittest.TestCase):
    def test_intact_chain_verifies(self):
        records = make_records(10)
        chained = build_chain(records)
        self.assertTrue(verify_chain(chained))
        self.assertIsNone(find_break_point(chained))

    def test_chain_length_matches_input(self):
        records = make_records(7)
        chained = build_chain(records)
        self.assertEqual(len(chained), 7)

    def test_modifying_a_record_breaks_chain_from_that_point(self):
        records = make_records(10)
        chained = build_chain(records)

        # On modifie le contenu d'un log APRES construction (simulateur de
        # falsification), sans recalculer la chaine -> doit etre detecte.
        chained[4].record.raw_log = "TAMPERED CONTENT"

        self.assertFalse(verify_chain(chained))
        self.assertEqual(find_break_point(chained), 4)

    def test_deleting_a_log_breaks_subsequent_chain(self):
        records = make_records(10)
        chained = build_chain(records)

        # Suppression du log a l'index 3 : la chaine stockee pour l'index 4
        # ne correspondra plus a previous_chain attendu (qui serait celui
        # de l'index 2 desormais).
        del chained[3]

        self.assertFalse(verify_chain(chained))
        # La rupture doit etre detectee a partir du nouvel index 3 (ancien index 4)
        self.assertEqual(find_break_point(chained), 3)

    def test_reordering_breaks_chain(self):
        records = make_records(10)
        chained = build_chain(records)

        chained[2], chained[5] = chained[5], chained[2]

        self.assertFalse(verify_chain(chained))

    def test_genesis_value_used_for_first_log(self):
        records = make_records(1)
        chained = build_chain(records)
        self.assertEqual(chained[0].previous_chain, GENESIS_CHAIN)


if __name__ == "__main__":
    unittest.main()
