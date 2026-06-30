"""
crypto/hash_chain.py

Serialisation canonique des logs et construction d'une chaine de hash.

Principe
--------
1. Chaque log est transforme en une representation canonique stable
   (canonical_log_i) en concatenant ses champs dans un ordre fixe, avec
   un separateur non-ambigu entre les champs.

2. leaf_i = H("LOG_LEAF" || canonical_log_i)
   -> hash de feuille, utilise ensuite comme feuille de l'arbre de Merkle.

3. chain_i = H("LOG_CHAIN" || chain_{i-1} || leaf_i)
   -> chaine les logs entre eux. Toute suppression ou tout
   reordonnancement casse cette chaine car chain_i depend de chain_{i-1}.

Tous les hash utilisent SHA-256.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional

# Separateur de champs choisi car tres improbable dans les donnees de log
# reelles (les champs texte du dataset BGL n'en contiennent pas).
FIELD_SEPARATOR = b"\x1f"  # ASCII Unit Separator

LEAF_DOMAIN = b"LOG_LEAF"
CHAIN_DOMAIN = b"LOG_CHAIN"

# Valeur de chain_0 (genesis), utilisee comme chain_{-1} pour le premier log
GENESIS_CHAIN = b"\x00" * 32


def sha256(data: bytes) -> bytes:
    """SHA-256 standard, retourne les bytes bruts du digest (32 octets)."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _to_bytes(value) -> bytes:
    """Convertit une valeur quelconque (str, int, None, float) en bytes UTF-8
    de maniere deterministe."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


@dataclass
class LogRecord:
    """Represente un log avec les champs necessaires a la canonicalisation.

    rawLogHash : hash (hex str) du contenu brut du log (raw_log). On hache le
    contenu brut separement plutot que de l'inclure tel quel, pour avoir une
    taille fixe et eviter qu'un message tres long ne domine la representation.
    """
    source_id: str
    seq_no: int
    timestamp: str  # representation textuelle stable (ISO 8601 recommande)
    event_id: str
    event_template: str
    raw_log: str

    def raw_log_hash_hex(self) -> str:
        return sha256_hex(_to_bytes(self.raw_log))


def canonical_log_bytes(record: LogRecord, previous_hash_hex: str) -> bytes:
    """Construit canonical_log_i :

        canonical_log_i = sourceId || seqNo || timestamp || eventId
                           || eventTemplate || rawLogHash || previousHash

    Les champs sont separes par FIELD_SEPARATOR pour eviter toute ambiguite
    de concatenation (ex: sourceId="12" + seqNo="3" vs sourceId="1" + seqNo="23").
    """
    fields = [
        _to_bytes(record.source_id),
        _to_bytes(record.seq_no),
        _to_bytes(record.timestamp),
        _to_bytes(record.event_id),
        _to_bytes(record.event_template),
        _to_bytes(record.raw_log_hash_hex()),
        _to_bytes(previous_hash_hex),
    ]
    return FIELD_SEPARATOR.join(fields)


def leaf_hash(record: LogRecord, previous_hash_hex: str) -> bytes:
    """leaf_i = H("LOG_LEAF" || canonical_log_i)"""
    canonical = canonical_log_bytes(record, previous_hash_hex)
    return sha256(LEAF_DOMAIN + FIELD_SEPARATOR + canonical)


def chain_hash(previous_chain_hash: bytes, leaf: bytes) -> bytes:
    """chain_i = H("LOG_CHAIN" || chain_{i-1} || leaf_i)"""
    return sha256(CHAIN_DOMAIN + FIELD_SEPARATOR + previous_chain_hash + FIELD_SEPARATOR + leaf)


@dataclass
class ChainedLog:
    """Un log apres passage dans la chaine : conserve le log original, son
    hash de feuille (leaf) et le hash de chaine (chain) a sa position."""
    record: LogRecord
    leaf: bytes
    chain: bytes
    previous_chain: bytes

    @property
    def leaf_hex(self) -> str:
        return self.leaf.hex()

    @property
    def chain_hex(self) -> str:
        return self.chain.hex()

    @property
    def previous_chain_hex(self) -> str:
        return self.previous_chain.hex()


def build_chain(records: List[LogRecord], genesis: bytes = GENESIS_CHAIN) -> List[ChainedLog]:
    """Construit la chaine complete pour une sequence de logs (dans l'ordre
    fourni). Retourne la liste des ChainedLog, un par log, dans le meme
    ordre.

    Toute modification de l'ordre, suppression d'un log, ou injection d'un
    log, change le resultat de chain_i pour tous les logs suivants : c'est
    la propriete de detection recherchee.
    """
    chained: List[ChainedLog] = []
    previous_chain = genesis
    previous_hash_hex = genesis.hex()

    for record in records:
        leaf = leaf_hash(record, previous_hash_hex)
        chain = chain_hash(previous_chain, leaf)
        chained.append(ChainedLog(
            record=record,
            leaf=leaf,
            chain=chain,
            previous_chain=previous_chain,
        ))
        previous_chain = chain
        previous_hash_hex = chain.hex()

    return chained


def verify_chain(chained: List[ChainedLog], genesis: bytes = GENESIS_CHAIN) -> bool:
    """Reverifie une chaine deja construite : recalcule chaque leaf_i et
    chain_i a partir des records et s'assure qu'ils correspondent aux
    valeurs stockees. Detecte toute alteration (suppression, modification,
    reordonnancement, injection) qui n'aurait pas ete suivie d'une mise a
    jour complete et correcte de la chaine.
    """
    previous_chain = genesis
    previous_hash_hex = genesis.hex()

    for entry in chained:
        expected_leaf = leaf_hash(entry.record, previous_hash_hex)
        if expected_leaf != entry.leaf:
            return False
        expected_chain = chain_hash(previous_chain, expected_leaf)
        if expected_chain != entry.chain:
            return False
        if entry.previous_chain != previous_chain:
            return False
        previous_chain = expected_chain
        previous_hash_hex = expected_chain.hex()

    return True


def find_break_point(chained: List[ChainedLog], genesis: bytes = GENESIS_CHAIN) -> Optional[int]:
    """Retourne l'index (0-based) du premier log a partir duquel la chaine
    ne correspond plus aux valeurs attendues, ou None si la chaine est
    intacte. Utile pour une preuve de falsification : localiser ou la
    chaine a ete rompue.
    """
    previous_chain = genesis
    previous_hash_hex = genesis.hex()

    for i, entry in enumerate(chained):
        expected_leaf = leaf_hash(entry.record, previous_hash_hex)
        expected_chain = chain_hash(previous_chain, expected_leaf)
        if expected_leaf != entry.leaf or expected_chain != entry.chain or entry.previous_chain != previous_chain:
            return i
        previous_chain = expected_chain
        previous_hash_hex = expected_chain.hex()

    return None
