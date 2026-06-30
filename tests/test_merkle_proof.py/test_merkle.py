"""Tests unitaires pour crypto/merkle.py"""

import sys
import os
import unittest
import hashlib
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.merkle import (
    compute_batch_id,
    group_into_batches,
    build_merkle_tree,
    generate_inclusion_proof,
    verify_inclusion_proof,
    merkle_root_only,
)


def leaf(i: int) -> bytes:
    return hashlib.sha256(f"leaf-{i}".encode()).digest()


class TestBatching(unittest.TestCase):
    def test_same_interval_same_batch_id(self):
        t1 = datetime(2005, 6, 3, 15, 42, 10, tzinfo=timezone.utc)
        t2 = datetime(2005, 6, 3, 15, 42, 50, tzinfo=timezone.utc)
        self.assertEqual(compute_batch_id(t1, 1), compute_batch_id(t2, 1))

    def test_different_interval_different_batch_id(self):
        t1 = datetime(2005, 6, 3, 15, 42, 10, tzinfo=timezone.utc)
        t2 = datetime(2005, 6, 3, 15, 44, 10, tzinfo=timezone.utc)
        self.assertNotEqual(compute_batch_id(t1, 1), compute_batch_id(t2, 1))

    def test_group_into_batches_groups_correctly(self):
        base = datetime(2005, 6, 3, 15, 40, 0, tzinfo=timezone.utc)
        timestamps = [base + timedelta(seconds=30 * i) for i in range(10)]
        items = list(range(10))
        batches = group_into_batches(items, timestamps, delta_minutes=1)
        # 30s entre logs, 1 min de batch -> 2 logs par batch environ
        total = sum(len(v) for v in batches.values())
        self.assertEqual(total, 10)
        self.assertGreaterEqual(len(batches), 4)

    def test_group_into_batches_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            group_into_batches([1, 2, 3], [datetime.now(timezone.utc)], delta_minutes=1)


class TestMerkleTreeConstruction(unittest.TestCase):
    def test_single_leaf_tree_root_equals_leaf(self):
        leaves = [leaf(0)]
        tree = build_merkle_tree(leaves)
        self.assertEqual(tree.root, leaves[0])

    def test_empty_leaves_raises(self):
        with self.assertRaises(ValueError):
            build_merkle_tree([])

    def test_root_changes_if_any_leaf_changes(self):
        leaves = [leaf(i) for i in range(8)]
        tree1 = build_merkle_tree(leaves)

        leaves2 = list(leaves)
        leaves2[3] = leaf(999)
        tree2 = build_merkle_tree(leaves2)

        self.assertNotEqual(tree1.root, tree2.root)

    def test_root_order_sensitive(self):
        leaves = [leaf(i) for i in range(4)]
        tree1 = build_merkle_tree(leaves)
        tree2 = build_merkle_tree(list(reversed(leaves)))
        self.assertNotEqual(tree1.root, tree2.root)

    def test_odd_number_of_leaves_handled(self):
        leaves = [leaf(i) for i in range(5)]  # nombre impair
        tree = build_merkle_tree(leaves)
        self.assertTrue(len(tree.root) == 32)

    def test_merkle_root_only_matches_full_tree(self):
        leaves = [leaf(i) for i in range(6)]
        root_only = merkle_root_only(leaves)
        full_tree = build_merkle_tree(leaves)
        self.assertEqual(root_only, full_tree.root)


class TestInclusionProof(unittest.TestCase):
    def test_proof_verifies_for_every_leaf_even_count(self):
        leaves = [leaf(i) for i in range(8)]
        tree = build_merkle_tree(leaves)
        for idx in range(len(leaves)):
            proof = generate_inclusion_proof(tree, idx, batch_id="batch-1")
            self.assertTrue(verify_inclusion_proof(proof), f"echec pour index {idx}")

    def test_proof_verifies_for_every_leaf_odd_count(self):
        leaves = [leaf(i) for i in range(7)]  # nombre impair -> duplication
        tree = build_merkle_tree(leaves)
        for idx in range(len(leaves)):
            proof = generate_inclusion_proof(tree, idx, batch_id="batch-2")
            self.assertTrue(verify_inclusion_proof(proof), f"echec pour index {idx}")

    def test_proof_verifies_single_leaf_tree(self):
        leaves = [leaf(0)]
        tree = build_merkle_tree(leaves)
        proof = generate_inclusion_proof(tree, 0, batch_id="batch-single")
        self.assertTrue(verify_inclusion_proof(proof))
        self.assertEqual(proof.sibling_hashes, [])

    def test_tampered_leaf_hash_fails_verification(self):
        leaves = [leaf(i) for i in range(8)]
        tree = build_merkle_tree(leaves)
        proof = generate_inclusion_proof(tree, 3, batch_id="batch-3")

        proof.leaf_hash = leaf(999)  # falsification de la feuille
        self.assertFalse(verify_inclusion_proof(proof))

    def test_tampered_sibling_fails_verification(self):
        leaves = [leaf(i) for i in range(8)]
        tree = build_merkle_tree(leaves)
        proof = generate_inclusion_proof(tree, 3, batch_id="batch-4")

        proof.sibling_hashes[0] = leaf(999)
        self.assertFalse(verify_inclusion_proof(proof))

    def test_swapped_direction_fails_verification(self):
        """Verifie que la direction gauche/droite est essentielle : si on
        l'inverse, la preuve doit (en general) echouer la verification."""
        leaves = [leaf(i) for i in range(8)]
        tree = build_merkle_tree(leaves)
        proof = generate_inclusion_proof(tree, 0, batch_id="batch-5")

        # Inverser toutes les directions
        proof.directions = [
            "right" if d == "left" else "left" for d in proof.directions
        ]
        self.assertFalse(verify_inclusion_proof(proof))

    def test_out_of_range_index_raises(self):
        leaves = [leaf(i) for i in range(4)]
        tree = build_merkle_tree(leaves)
        with self.assertRaises(IndexError):
            generate_inclusion_proof(tree, 99, batch_id="batch-6")

    def test_proof_to_dict_roundtrip_fields(self):
        leaves = [leaf(i) for i in range(4)]
        tree = build_merkle_tree(leaves)
        proof = generate_inclusion_proof(tree, 2, batch_id="batch-7")
        d = proof.to_dict()
        self.assertEqual(d["batch_id"], "batch-7")
        self.assertEqual(d["leaf_index"], 2)
        self.assertEqual(len(d["sibling_hashes"]), len(d["directions"]))


if __name__ == "__main__":
    unittest.main()
