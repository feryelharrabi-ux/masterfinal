"""
crypto/merkle.py

Regroupement des logs en lots (batches) par intervalle de temps, construction
d'un arbre de Merkle par batch, et generation/verification de preuves
d'inclusion.

Batching
--------
Les logs sont regroupes par intervalle de temps Delta_t (1, 5 ou 10 minutes).
Un batch_id est calcule a partir du debut de l'intervalle (floor du
timestamp sur Delta_t).

Arbre de Merkle
---------------
- Feuilles : les leaf_i produits par crypto.hash_chain (deja prefixees par
  le domaine "LOG_LEAF").
- Noeud interne : H("LOG_NODE" || left || right)
- Si le nombre de feuilles est impair a un niveau, la derniere feuille est
  dupliquee (regle standard de Merkle pour completer la paire). On marque
  ce cas explicitement dans la preuve pour ne pas fausser la verification.

Preuve d'inclusion
-------------------
Pour une feuille donnee, la preuve contient :
- leaf_hash       : hash de la feuille a prouver
- sibling_hashes  : liste des hash des voisins, du bas vers la racine
- directions      : pour chaque sibling, indique si le sibling est a
                    gauche ("left") ou a droite ("right") du noeud courant.
                    C'est indispensable car H(a||b) != H(b||a) ; sans cette
                    information, la verification peut echouer ou pire,
                    valider une preuve incorrecte par coincidence.
- root            : la racine de Merkle attendue
- batch_id        : l'identifiant du batch concerne
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence

NODE_DOMAIN = b"LOG_NODE"
LEAF_PASS_DOMAIN = b"LOG_LEAF_NODE"  # utilise quand une feuille est promue telle quelle


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------
# Batching par intervalle de temps
# --------------------------------------------------------------------------
def compute_batch_id(timestamp: datetime, delta_minutes: int) -> str:
    """Calcule un identifiant de batch a partir d'un timestamp et d'un
    intervalle Delta_t (en minutes). Le batch_id est le debut de
    l'intervalle au format ISO 8601, ce qui le rend lisible et trie.
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    epoch_minutes = timestamp.timestamp() / 60.0
    bucket_index = math.floor(epoch_minutes / delta_minutes)
    bucket_start_seconds = bucket_index * delta_minutes * 60
    bucket_start = datetime.fromtimestamp(bucket_start_seconds, tz=timezone.utc)
    return bucket_start.strftime("%Y-%m-%dT%H:%M:%SZ") + f"|dt{delta_minutes}m"


def group_into_batches(items: Sequence, timestamps: Sequence[datetime], delta_minutes: int) -> Dict[str, List]:
    """Regroupe une sequence d'objets (ex: ChainedLog) par intervalle de
    temps Delta_t, en se basant sur la sequence parallele de timestamps.

    Retourne un dict batch_id -> liste d'objets, dans l'ordre d'apparition.
    """
    if len(items) != len(timestamps):
        raise ValueError("items et timestamps doivent avoir la meme longueur")

    batches: Dict[str, List] = {}
    for item, ts in zip(items, timestamps):
        batch_id = compute_batch_id(ts, delta_minutes)
        batches.setdefault(batch_id, []).append(item)
    return batches


# --------------------------------------------------------------------------
# Arbre de Merkle
# --------------------------------------------------------------------------
@dataclass
class MerkleTree:
    """Arbre de Merkle construit a partir d'une liste de feuilles (bytes).

    levels[0] = feuilles (eventuellement avec duplication pour completer
                les paires impaires)
    levels[-1] = [root]
    """
    leaves: List[bytes]
    levels: List[List[bytes]] = field(default_factory=list)
    # Pour chaque niveau, indique si le dernier element est une duplication
    # du precedent (cas de nombre impair de noeuds a ce niveau).
    padded_at_level: List[bool] = field(default_factory=list)

    @property
    def root(self) -> bytes:
        if not self.levels:
            raise ValueError("Arbre vide : aucune feuille fournie.")
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_DOMAIN + left + right)


def build_merkle_tree(leaves: Sequence[bytes]) -> MerkleTree:
    """Construit l'arbre complet a partir d'une liste de feuilles non vide.

    Regle pour nombre impair de noeuds a un niveau : on duplique le dernier
    noeud pour former la derniere paire. C'est consigne dans
    padded_at_level pour que la generation/verification de preuve en tienne
    compte explicitement.
    """
    if not leaves:
        raise ValueError("Impossible de construire un arbre de Merkle sans feuilles.")

    levels: List[List[bytes]] = [list(leaves)]
    padded_at_level: List[bool] = []

    current = list(leaves)
    while len(current) > 1:
        padded = False
        if len(current) % 2 == 1:
            current = current + [current[-1]]
            padded = True
        padded_at_level.append(padded)

        next_level = []
        for i in range(0, len(current), 2):
            next_level.append(_hash_pair(current[i], current[i + 1]))
        levels.append(next_level)
        current = next_level

    # Le dernier niveau a une seule feuille (pas de padding necessaire) :
    # on ajoute False pour homogeneite si la boucle ne s'est jamais executee
    if not padded_at_level:
        padded_at_level.append(False)

    return MerkleTree(leaves=list(leaves), levels=levels, padded_at_level=padded_at_level)


# --------------------------------------------------------------------------
# Preuve d'inclusion
# --------------------------------------------------------------------------
@dataclass
class MerkleProofStep:
    sibling_hash: bytes
    direction: str  # "left" ou "right" : position du SIBLING par rapport au noeud courant

    @property
    def sibling_hash_hex(self) -> str:
        return self.sibling_hash.hex()


@dataclass
class MerkleProof:
    leaf_hash: bytes
    sibling_hashes: List[bytes]
    directions: List[str]
    root: bytes
    batch_id: str
    leaf_index: int

    @property
    def leaf_hash_hex(self) -> str:
        return self.leaf_hash.hex()

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def to_dict(self) -> dict:
        return {
            "leaf_hash": self.leaf_hash_hex,
            "sibling_hashes": [h.hex() for h in self.sibling_hashes],
            "directions": list(self.directions),
            "root": self.root_hex,
            "batch_id": self.batch_id,
            "leaf_index": self.leaf_index,
        }


def generate_inclusion_proof(tree: MerkleTree, leaf_index: int, batch_id: str) -> MerkleProof:
    """Genere une preuve d'inclusion pour la feuille situee a leaf_index
    (0-based, dans l'ordre original des feuilles fournies a build_merkle_tree).

    A chaque niveau, on retrouve le voisin (sibling) du noeud courant et on
    enregistre sa position (gauche/droite) relativement au noeud courant.
    Cette information de direction est essentielle : H(a||b) != H(b||a).
    """
    if leaf_index < 0 or leaf_index >= len(tree.leaves):
        raise IndexError(f"leaf_index {leaf_index} hors limites (0..{len(tree.leaves)-1})")

    sibling_hashes: List[bytes] = []
    directions: List[str] = []

    index = leaf_index
    for level_idx in range(len(tree.levels) - 1):
        level = list(tree.levels[level_idx])
        if tree.padded_at_level[level_idx] and len(level) % 2 == 1:
            level = level + [level[-1]]

        is_right_node = index % 2 == 1
        if is_right_node:
            sibling_index = index - 1
            direction = "left"  # le sibling est a gauche du noeud courant
        else:
            sibling_index = index + 1
            direction = "right"  # le sibling est a droite du noeud courant

        sibling_hashes.append(level[sibling_index])
        directions.append(direction)

        index = index // 2

    return MerkleProof(
        leaf_hash=tree.leaves[leaf_index],
        sibling_hashes=sibling_hashes,
        directions=directions,
        root=tree.root,
        batch_id=batch_id,
        leaf_index=leaf_index,
    )


def verify_inclusion_proof(proof: MerkleProof) -> bool:
    """Reconstruit la racine a partir de leaf_hash + sibling_hashes +
    directions, et compare au root fourni dans la preuve.

    Pour chaque etape :
      - si direction == "left"  : le sibling est a gauche -> H(sibling || courant)
      - si direction == "right" : le sibling est a droite  -> H(courant || sibling)
    """
    if len(proof.sibling_hashes) != len(proof.directions):
        return False

    current = proof.leaf_hash
    for sibling, direction in zip(proof.sibling_hashes, proof.directions):
        if direction == "left":
            current = _hash_pair(sibling, current)
        elif direction == "right":
            current = _hash_pair(current, sibling)
        else:
            return False  # direction invalide -> preuve rejetee

    return current == proof.root


def merkle_root_only(leaves: Sequence[bytes]) -> bytes:
    """Raccourci : calcule juste la racine de Merkle sans garder l'arbre
    complet en memoire (utile quand on n'a pas besoin de generer de preuve
    pour ce batch)."""
    return build_merkle_tree(leaves).root
