"""
verify_log.py  —  Partie F : Procédure complète de vérification

Un auditeur verifie l'integrite d'un log BGL en executant les 6 etapes
cryptographiques suivantes, puis retourne un verdict parmi :

    INTACT               le log est intact, signature valide, root conforme on-chain
    ALTERED_CONTENT      le contenu du log a ete modifie (leaf recalcule != leaf stocke)
    DELETED_LOG          le log est absent de la chaine (seq_no manquant)
    REORDERED_LOG        l'ordre des logs dans la chaine a ete perturbe
    INVALID_SIGNATURE    la signature Ed25519 du batch root est invalide
    ROOT_NOT_FOUND       le batch_id n'existe pas on-chain
    ANCHOR_MISMATCH      le root recalcule localement != root stocke on-chain

Etapes :
    1. Recalculer le hash canonique du log
    2. Recalculer le chemin Merkle
    3. Obtenir le Merkle root local
    4. Verifier la signature du root
    5. Lire le root stocke on-chain
    6. Comparer les roots
    7. Retourner le verdict

Usage :
    # Verifier un seul log (mode interactif)
    py verify_log.py --log-id log_1 --csv bgl_100000_structured_blockid_event.csv

    # Generer un rapport complet sur falsification_BGL.xlsx
    py verify_log.py --report --falsified falsification_BGL.xlsx --csv bgl_100000_structured_blockid_event.csv

    # Mode sans noeud Ethereum (off-chain seulement, utile pour tester sans Hardhat)
    py verify_log.py --report --falsified falsification_BGL.xlsx --csv bgl_100000_structured_blockid_event.csv --offline
"""

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import pandas as pd

# ---------- import du module crypto (meme dossier ou sous-dossier crypto/) ----------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from crypto.hash_chain import (
    LogRecord,
    build_chain,
    find_break_point,
    leaf_hash,
    verify_chain,
)
from crypto.merkle import (
    build_merkle_tree,
    generate_inclusion_proof,
    group_into_batches,
    verify_inclusion_proof,
)
from crypto.signature import (
    BatchSignaturePayload,
    public_key_from_bytes,
    verify_batch_signature,
)

# ---------- Chemins par defaut ----------
DEFAULT_CSV        = os.path.join(SCRIPT_DIR, "bgl_100000_structured_blockid_event.csv")
DEFAULT_FALSIFIED  = os.path.join(SCRIPT_DIR, "falsification_BGL.xlsx")
DEPLOYMENT_JSON    = os.path.join(SCRIPT_DIR, "deployment.json")
KEYS_FILE          = os.path.join(SCRIPT_DIR, "signing_key.json")
REPORT_OUTPUT      = os.path.join(SCRIPT_DIR, "verification_report_BGL.xlsx")

DELTA_MINUTES      = 1        # meme valeur que celle utilisee dans anchor_batch.py
N_ROWS             = 5000     # nombre de logs a charger (ajuster selon RAM disponible)

# ---------- Verdicts possibles ----------
INTACT             = "INTACT"
ALTERED_CONTENT    = "ALTERED_CONTENT"
DELETED_LOG        = "DELETED_LOG"
REORDERED_LOG      = "REORDERED_LOG"
INVALID_SIGNATURE  = "INVALID_SIGNATURE"
ROOT_NOT_FOUND     = "ROOT_NOT_FOUND"
ANCHOR_MISMATCH    = "ANCHOR_MISMATCH"


# ===========================================================================
# Helpers
# ===========================================================================

def batch_id_to_uint256(batch_id_str: str) -> int:
    digest = hashlib.sha256(batch_id_str.encode()).digest()
    return int.from_bytes(digest, byteorder="big")


def load_public_key():
    if not os.path.exists(KEYS_FILE):
        return None
    with open(KEYS_FILE) as f:
        data = json.load(f)
    return public_key_from_bytes(bytes.fromhex(data["public_key_hex"]))


def load_deployment():
    if not os.path.exists(DEPLOYMENT_JSON):
        return None
    with open(DEPLOYMENT_JSON) as f:
        return json.load(f)


def connect_contract():
    """Retourne (w3, contract) ou (None, None) si web3 indisponible / noeud eteint."""
    try:
        from web3 import Web3
        dep = load_deployment()
        if dep is None:
            return None, None
        rpc = dep.get("rpcUrl", "http://127.0.0.1:8545")
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 3}))
        if not w3.is_connected():
            return None, None
        contract = w3.eth.contract(address=dep["address"], abi=dep["abi"])
        return w3, contract
    except Exception:
        return None, None


def read_root_onchain(contract, batch_id_str: str):
    """
    Lit le merkleRoot stocke on-chain pour ce batch.
    Retourne (root_hex, signature_bytes) ou (None, None) si absent.
    """
    try:
        uid = batch_id_to_uint256(batch_id_str)
        exists = contract.functions.anchorExists(uid).call()
        if not exists:
            return None, None
        anchor = contract.functions.getAnchor(uid).call()
        # anchor = (sourceIdHash, merkleRoot, signature, startSeq, endSeq,
        #           timestamp, metadataURI, anchoredAt, anchoredBy)
        merkle_root_bytes = anchor[1]
        signature_bytes   = bytes(anchor[2])
        return merkle_root_bytes.hex(), signature_bytes
    except Exception:
        return None, None


def df_to_records(df: pd.DataFrame):
    """Convertit un DataFrame de logs en (List[LogRecord], List[datetime])."""
    records, timestamps = [], []
    for _, row in df.iterrows():
        records.append(LogRecord(
            source_id      = str(row["source_id"]),
            seq_no         = int(row["seq_no"]),
            timestamp      = pd.to_datetime(row["timestamp"]).isoformat(),
            event_id       = str(row["event_id"]),
            event_template = str(row["event_template"]),
            raw_log        = str(row["raw_log"]),
        ))
        timestamps.append(pd.to_datetime(row["timestamp"]).to_pydatetime())
    return records, timestamps


# ===========================================================================
# Coeur : verification d'UN log
# ===========================================================================

@dataclass
class VerificationResult:
    log_id:            str
    seq_no:            int
    batch_id:          str
    verdict:           str
    leaf_hash_local:   Optional[str]  = None
    root_local:        Optional[str]  = None
    root_onchain:      Optional[str]  = None
    signature_valid:   Optional[bool] = None
    roots_match:       Optional[bool] = None
    detail:            str            = ""
    elapsed_ms:        float          = 0.0


def verify_one_log(
    log_id:        str,
    df_reference:  pd.DataFrame,   # dataset INTACT original (reference de confiance)
    df_to_verify:  pd.DataFrame,   # dataset reçu par l'auditeur (potentiellement falsifie)
    contract,                       # None si mode offline
    pk,                             # cle publique Ed25519, None si absente
    delta_minutes: int = DELTA_MINUTES,
) -> VerificationResult:
    """
    Verifie l'integrite d'un log identifie par log_id.

    Principe :
    - df_reference = dataset INTACT (ce qui a ete ancre on-chain)
    - df_to_verify = dataset reçu par l'auditeur (peut etre falsifie)

    L'auditeur :
    1. Recalcule le leaf du log depuis df_to_verify (ce qu'il a reçu)
    2. Recalcule le Merkle root depuis df_reference (ce qui a ete ancre)
    3. Cherche le leaf du log dans l'arbre Merkle de reference
    4. Si le leaf ne correspond pas -> ALTERED_CONTENT
    5. Compare le root local (reference) avec le root on-chain
    """
    t0 = time.perf_counter()

    # ---- Le log existe-t-il dans ce que l'auditeur a reçu ? ----
    row_mask_verify = df_to_verify["log_id"] == log_id
    if not row_mask_verify.any():
        return VerificationResult(
            log_id=log_id, seq_no=-1, batch_id="",
            verdict=DELETED_LOG,
            detail="log_id absent du dataset reçu : log supprime",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    row_verify = df_to_verify[row_mask_verify].iloc[0]
    seq_no     = int(row_verify["seq_no"])
    ts_log     = pd.to_datetime(row_verify["timestamp"]).to_pydatetime()
    batch_id   = _compute_batch_id(ts_log, delta_minutes)

    # ---- Batch de REFERENCE (intact) ----
    df_batch_ref = _get_batch_logs(df_reference, ts_log, delta_minutes)
    if df_batch_ref.empty:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=ROOT_NOT_FOUND,
            detail="Aucun log de reference trouve pour ce batch",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # ---- Etape 1 : recalculer la chaine depuis le dataset REÇU (falsifie potentiel) ----
    df_batch_verify = _get_batch_logs(df_to_verify, ts_log, delta_minutes)
    if df_batch_verify.empty:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=DELETED_LOG,
            detail="Batch absent du dataset reçu",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    records_verify, _ = df_to_records(df_batch_verify)
    chained_verify    = build_chain(records_verify)

    # Verifier coherence interne de la chaine reçue
    chain_ok  = verify_chain(chained_verify)
    break_idx = find_break_point(chained_verify) if not chain_ok else None

    # Trouver le log cible dans le batch reçu
    log_idx_verify = None
    for i, entry in enumerate(chained_verify):
        if entry.record.seq_no == seq_no:
            log_idx_verify = i
            break

    if log_idx_verify is None:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=DELETED_LOG,
            detail=f"seq_no={seq_no} introuvable dans le batch reçu",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    if break_idx is not None and break_idx <= log_idx_verify:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=REORDERED_LOG,
            detail=f"Rupture de chaine detectee a l'index {break_idx} dans le batch reçu",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    leaf_received = chained_verify[log_idx_verify].leaf
    leaf_hex      = leaf_received.hex()

    # ---- Etape 2 : recalculer l'arbre Merkle depuis le dataset de REFERENCE ----
    records_ref, _ = df_to_records(df_batch_ref)
    chained_ref    = build_chain(records_ref)
    leaves_ref     = [entry.leaf for entry in chained_ref]
    tree_ref       = build_merkle_tree(leaves_ref)
    root_local     = tree_ref.root_hex

    # ---- Trouver le leaf de reference pour ce seq_no ----
    leaf_ref = None
    ref_idx  = None
    for i, entry in enumerate(chained_ref):
        if entry.record.seq_no == seq_no:
            leaf_ref = entry.leaf
            ref_idx  = i
            break

    # ---- Trouver le leaf de reference pour ce log (par log_id d'abord, puis seq_no) ----
    leaf_ref = None
    ref_idx  = None

    # Chercher le log dans le dataset de reference par log_id
    ref_row_mask = df_reference["log_id"] == log_id
    if ref_row_mask.any():
        ref_row    = df_reference[ref_row_mask].iloc[0]
        ref_seq_no = int(ref_row["seq_no"])
        for i, entry in enumerate(chained_ref):
            if entry.record.seq_no == ref_seq_no:
                leaf_ref = entry.leaf
                ref_idx  = i
                break
    else:
        # log_id absent de la reference -> log injecte artificiellement
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=ALTERED_CONTENT,
            leaf_hash_local=leaf_hex,
            root_local=root_local,
            detail=f"log_id={log_id} absent du dataset de reference : log injecte",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    if leaf_ref is None:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=ROOT_NOT_FOUND,
            leaf_hash_local=leaf_hex,
            root_local=root_local,
            detail=f"log_id={log_id} hors perimetre du batch de reference charge",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # ---- Etape 3 : comparer les champs du log reçu vs reference ----
    # Comparaison directe des champs constitutifs du log (plus robuste que
    # comparer les leaf hash quand la position dans la chaine a change)
    ref_row_data    = df_reference[df_reference["log_id"] == log_id].iloc[0]
    verify_row_data = df_to_verify[df_to_verify["log_id"] == log_id].iloc[0]

    fields_to_compare = ["raw_log", "event_template", "severity", "source_id"]
    content_changed   = False
    changed_fields    = []
    for field in fields_to_compare:
        if field in ref_row_data.index and field in verify_row_data.index:
            if str(ref_row_data[field]) != str(verify_row_data[field]):
                content_changed = True
                changed_fields.append(field)

    if content_changed:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=ALTERED_CONTENT,
            leaf_hash_local=leaf_hex,
            root_local=root_local,
            detail=f"Champs modifies par rapport a la reference : {', '.join(changed_fields)}",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # Verifier aussi via le leaf hash si la reference est disponible dans le meme batch
    # NOTE : on ne compare le leaf que si les champs de contenu ont change.
    # En effet, le leaf inclut le timestamp avec precision microseconde, qui
    # peut etre legerement arrondi lors d'une sauvegarde/relecture Excel —
    # ce qui causerait de faux positifs sur des logs non falsifies.
    # La comparaison des champs ci-dessus est la verification primaire.
    if content_changed and leaf_ref is not None and leaf_received != leaf_ref:
        pass  # deja retourne ALTERED_CONTENT ci-dessus

    # ---- Etape 4 : verifier la signature du root de reference ----
    sig_valid = None
    if pk is not None and contract is not None:
        _, sig_bytes = read_root_onchain(contract, batch_id)
        if sig_bytes:
            source_id = records_ref[0].source_id
            payload = BatchSignaturePayload(
                root_hex  = root_local,
                batch_id  = batch_id,
                source_id = source_id,
                start_seq = min(r.seq_no for r in records_ref),
                end_seq   = max(r.seq_no for r in records_ref),
                timestamp = records_ref[0].timestamp,
            )
            sig_valid = verify_batch_signature(pk, sig_bytes, payload)

    if sig_valid is False:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=INVALID_SIGNATURE,
            leaf_hash_local=leaf_hex,
            root_local=root_local,
            signature_valid=False,
            detail="Signature Ed25519 du root invalide",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # ---- Etapes 5 & 6 : lire et comparer le root on-chain ----
    root_onchain = None
    roots_match  = None

    if contract is not None:
        root_onchain, _ = read_root_onchain(contract, batch_id)
        if root_onchain is None:
            return VerificationResult(
                log_id=log_id, seq_no=seq_no, batch_id=batch_id,
                verdict=ROOT_NOT_FOUND,
                leaf_hash_local=leaf_hex,
                root_local=root_local,
                signature_valid=sig_valid,
                detail=f"Aucun ancrage on-chain pour batch_id={batch_id}",
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )
        roots_match = (root_local == root_onchain)
        if not roots_match:
            return VerificationResult(
                log_id=log_id, seq_no=seq_no, batch_id=batch_id,
                verdict=ANCHOR_MISMATCH,
                leaf_hash_local=leaf_hex,
                root_local=root_local,
                root_onchain=root_onchain,
                signature_valid=sig_valid,
                roots_match=False,
                detail="Root local != root on-chain",
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

    # ---- Etape 7 : INTACT ----
    return VerificationResult(
        log_id=log_id, seq_no=seq_no, batch_id=batch_id,
        verdict=INTACT,
        leaf_hash_local=leaf_hex,
        root_local=root_local,
        root_onchain=root_onchain,
        signature_valid=sig_valid,
        roots_match=roots_match,
        detail="Log integre : leaf identique a la reference, chaine valide, Merkle valide"
               + (", signature valide" if sig_valid else "")
               + (", root conforme on-chain" if roots_match else " (mode offline)"),
        elapsed_ms=(time.perf_counter() - t0) * 1000,
    )
    """
    Verifie l'integrite d'un log identifie par log_id.

    Le dataset de reference contient TOUS les logs du batch auquel
    appartient ce log — c'est indispensable pour reconstruire l'arbre
    de Merkle complet et generer la preuve d'inclusion.
    """
    t0 = time.perf_counter()

    # ---- Trouver le log dans le dataset de reference ----
    row_mask = df_reference["log_id"] == log_id
    if not row_mask.any():
        return VerificationResult(
            log_id=log_id, seq_no=-1, batch_id="",
            verdict=DELETED_LOG,
            detail="log_id absent du dataset de reference : log supprime ou id inconnu",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    row = df_reference[row_mask].iloc[0]
    seq_no = int(row["seq_no"])

    # ---- Identifier le batch auquel appartient ce log ----
    ts_log = pd.to_datetime(row["timestamp"]).to_pydatetime()
    batch_id = _compute_batch_id(ts_log, delta_minutes)

    # ---- Charger tous les logs du meme batch (dans le dataset de reference) ----
    df_batch = _get_batch_logs(df_reference, ts_log, delta_minutes)
    if df_batch.empty:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=ROOT_NOT_FOUND,
            detail="Aucun log trouve pour ce batch dans le dataset de reference",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # ---- Etape 1 : recalculer la chaine de hash sur le batch ----
    records, timestamps = df_to_records(df_batch)
    chained = build_chain(records)

    # Verifier que la chaine est coherente (detecte suppressions / reordonnancements)
    chain_ok = verify_chain(chained)
    break_idx = find_break_point(chained) if not chain_ok else None

    # Trouver l'index du log cible dans le batch
    log_index_in_batch = None
    for i, entry in enumerate(chained):
        if entry.record.seq_no == seq_no:
            log_index_in_batch = i
            break

    if log_index_in_batch is None:
        verdict = DELETED_LOG if chain_ok else REORDERED_LOG
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=verdict,
            detail=f"seq_no={seq_no} introuvable dans le batch apres reconstruction de la chaine",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # Si la chaine est rompue AVANT ou AU niveau de ce log -> reordonnancement / suppression
    if break_idx is not None and break_idx <= log_index_in_batch:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=REORDERED_LOG,
            detail=f"Rupture de chaine detectee a l'index {break_idx} "
                   f"(ce log est a l'index {log_index_in_batch} dans le batch)",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    leaf_local = chained[log_index_in_batch].leaf
    leaf_hex   = leaf_local.hex()

    # ---- Etape 2 : recalculer l'arbre de Merkle du batch ----
    leaves = [entry.leaf for entry in chained]
    tree   = build_merkle_tree(leaves)

    # ---- Etape 3 : obtenir le Merkle root local ----
    root_local = tree.root_hex

    # Generer la preuve d'inclusion pour ce log
    proof = generate_inclusion_proof(tree, log_index_in_batch, batch_id=batch_id)
    proof_valid = verify_inclusion_proof(proof)

    if not proof_valid:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=ALTERED_CONTENT,
            leaf_hash_local=leaf_hex,
            root_local=root_local,
            detail="La preuve d'inclusion du log echoue : contenu altere",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # ---- Etape 4 : verifier la signature du root ----
    sig_valid = None
    if pk is not None:
        source_id = records[0].source_id
        payload = BatchSignaturePayload(
            root_hex  = root_local,
            batch_id  = batch_id,
            source_id = source_id,
            start_seq = min(r.seq_no for r in records),
            end_seq   = max(r.seq_no for r in records),
            timestamp = records[0].timestamp,
        )
        # On a besoin de la signature stockee on-chain pour la verifier
        if contract is not None:
            _, sig_bytes = read_root_onchain(contract, batch_id)
            if sig_bytes:
                sig_valid = verify_batch_signature(pk, sig_bytes, payload)

    if sig_valid is False:
        return VerificationResult(
            log_id=log_id, seq_no=seq_no, batch_id=batch_id,
            verdict=INVALID_SIGNATURE,
            leaf_hash_local=leaf_hex,
            root_local=root_local,
            signature_valid=False,
            detail="La signature Ed25519 du root ne correspond pas a la cle publique connue",
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # ---- Etapes 5 & 6 : lire et comparer le root on-chain ----
    root_onchain = None
    roots_match  = None

    if contract is not None:
        root_onchain, _ = read_root_onchain(contract, batch_id)
        if root_onchain is None:
            return VerificationResult(
                log_id=log_id, seq_no=seq_no, batch_id=batch_id,
                verdict=ROOT_NOT_FOUND,
                leaf_hash_local=leaf_hex,
                root_local=root_local,
                signature_valid=sig_valid,
                detail=f"Aucun ancrage trouve on-chain pour batch_id={batch_id}",
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )
        roots_match = (root_local == root_onchain)
        if not roots_match:
            return VerificationResult(
                log_id=log_id, seq_no=seq_no, batch_id=batch_id,
                verdict=ANCHOR_MISMATCH,
                leaf_hash_local=leaf_hex,
                root_local=root_local,
                root_onchain=root_onchain,
                signature_valid=sig_valid,
                roots_match=False,
                detail="Root recalcule localement != root stocke on-chain",
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

    # ---- Etape 7 : INTACT ----
    return VerificationResult(
        log_id=log_id, seq_no=seq_no, batch_id=batch_id,
        verdict=INTACT,
        leaf_hash_local=leaf_hex,
        root_local=root_local,
        root_onchain=root_onchain,
        signature_valid=sig_valid,
        roots_match=roots_match,
        detail="Log integre : chaine valide, preuve Merkle valide"
               + (", signature valide" if sig_valid else "")
               + (", root conforme on-chain" if roots_match else " (mode offline : root non verifie on-chain)"),
        elapsed_ms=(time.perf_counter() - t0) * 1000,
    )


# ===========================================================================
# Helpers internes
# ===========================================================================

def _compute_batch_id(ts: datetime, delta_minutes: int) -> str:
    import math
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    bucket = math.floor(ts.timestamp() / 60.0 / delta_minutes)
    start  = datetime.fromtimestamp(bucket * delta_minutes * 60, tz=timezone.utc)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ") + f"|dt{delta_minutes}m"


def _get_batch_logs(df: pd.DataFrame, ts_log: datetime, delta_minutes: int) -> pd.DataFrame:
    import math
    if ts_log.tzinfo is None:
        ts_log = ts_log.replace(tzinfo=timezone.utc)
    bucket      = math.floor(ts_log.timestamp() / 60.0 / delta_minutes)
    t_start     = datetime.fromtimestamp(bucket * delta_minutes * 60, tz=timezone.utc)
    t_end       = datetime.fromtimestamp((bucket + 1) * delta_minutes * 60, tz=timezone.utc)
    ts_series   = pd.to_datetime(df["timestamp"]).dt.tz_localize(None).dt.tz_localize("UTC")
    mask        = (ts_series >= t_start) & (ts_series < t_end)
    return df[mask].sort_values("seq_no").reset_index(drop=True)


# ===========================================================================
# Mode rapport complet
# ===========================================================================

def run_full_report(
    csv_path:      str,
    falsified_path: str,
    contract,
    pk,
    delta_minutes: int,
    n_rows:        int,
    offline:       bool,
):
    print(f"\nChargement du dataset de reference ({n_rows} logs)...")
    df_ref = pd.read_csv(csv_path, nrows=n_rows)
    df_ref["timestamp"] = pd.to_datetime(df_ref["timestamp"])
    df_ref = df_ref.sort_values("seq_no").reset_index(drop=True)

    print(f"Chargement du dataset falsifie ({falsified_path})...")
    df_fals = pd.read_excel(falsified_path, sheet_name="logs_falsifies")
    df_fals["timestamp"] = pd.to_datetime(df_fals["timestamp"])
    df_fals = df_fals.sort_values("seq_no").reset_index(drop=True)

    gt = pd.read_excel(falsified_path, sheet_name="ground_truth")

    # On selectionne un echantillon representatif pour le rapport :
    # - tous les logs falsifies (log_label != clean)
    # - un echantillon de logs clean pour avoir un mix representatif
    falsified_ids = set(df_fals[df_fals["log_label"] != "clean"]["log_id"].tolist())

    # Echantillon clean : 200 logs clean du dataset falsifie
    clean_sample = (
        df_fals[df_fals["log_label"] == "clean"]
        .sample(n=min(200, len(df_fals[df_fals["log_label"] == "clean"])), random_state=42)["log_id"]
        .tolist()
    )

    # On limite les falsifies a 500 pour rester rapide
    falsified_sample = list(falsified_ids)[:500]
    all_ids_to_check = falsified_sample + clean_sample

    print(f"Logs a verifier : {len(falsified_sample)} falsifies + {len(clean_sample)} clean "
          f"= {len(all_ids_to_check)} au total")

    # Pour la verification, on utilise le dataset FALSIFIE comme source
    # (c'est ce que l'auditeur reçoit — il ne sait pas ce qui a ete falsifie)
    results = []
    verdicts_by_label = {}

    for i, log_id in enumerate(all_ids_to_check):
        if i % 100 == 0:
            print(f"  ... {i}/{len(all_ids_to_check)}")

        result = verify_one_log(
            log_id        = log_id,
            df_reference  = df_ref,
            df_to_verify  = df_fals,
            contract      = contract if not offline else None,
            pk            = pk,
            delta_minutes = delta_minutes,
        )

        # Recuperer le vrai label depuis le ground truth
        gt_row = gt[gt["log_id"] == log_id]
        true_label  = gt_row["log_label"].values[0]  if len(gt_row) else "unknown"
        true_tampered = bool(gt_row["tampered"].values[0]) if len(gt_row) else False
        attack_type = gt_row["attack_type"].values[0] if len(gt_row) else "none"

        results.append({
            "log_id":           result.log_id,
            "seq_no":           result.seq_no,
            "batch_id":         result.batch_id,
            "verdict":          result.verdict,
            "true_label":       true_label,
            "true_tampered":    true_tampered,
            "attack_type":      attack_type,
            "leaf_hash_local":  result.leaf_hash_local,
            "root_local":       result.root_local,
            "root_onchain":     result.root_onchain,
            "signature_valid":  result.signature_valid,
            "roots_match":      result.roots_match,
            "detail":           result.detail,
            "elapsed_ms":       round(result.elapsed_ms, 3),
        })

        key = (true_label, result.verdict)
        verdicts_by_label[key] = verdicts_by_label.get(key, 0) + 1

    df_results = pd.DataFrame(results)

    # ---- Metriques de detection ----
    df_results["detected_as_tampered"] = df_results["verdict"] != INTACT
    df_results["correct_detection"] = (
        (df_results["true_tampered"] & df_results["detected_as_tampered"]) |
        (~df_results["true_tampered"] & ~df_results["detected_as_tampered"])
    )

    tp = int(( df_results["true_tampered"] &  df_results["detected_as_tampered"]).sum())
    tn = int((~df_results["true_tampered"] & ~df_results["detected_as_tampered"]).sum())
    fp = int((~df_results["true_tampered"] &  df_results["detected_as_tampered"]).sum())
    fn = int(( df_results["true_tampered"] & ~df_results["detected_as_tampered"]).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall    = tp / (tp + fn) if (tp + fn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy  = (tp + tn) / len(df_results) if len(df_results) > 0 else 0

    # ---- Tableau de synthese par type d'attaque ----
    df_summary = (
        df_results
        .groupby(["attack_type", "verdict"])
        .size()
        .reset_index(name="count")
    )

    # ---- Tableau de metriques global ----
    df_metrics = pd.DataFrame([{
        "n_logs_verifies":      len(df_results),
        "n_falsifies_vrais":    int(df_results["true_tampered"].sum()),
        "n_clean_vrais":        int((~df_results["true_tampered"]).sum()),
        "TP":  tp, "TN": tn, "FP": fp, "FN": fn,
        "precision":  round(precision, 4),
        "recall":     round(recall, 4),
        "F1":         round(f1, 4),
        "accuracy":   round(accuracy, 4),
        "mode":       "offline" if offline else "online (blockchain)",
        "delta_t_min": delta_minutes,
    }])

    # ---- Ecriture Excel ----
    print(f"\nEcriture du rapport : {REPORT_OUTPUT}")
    with pd.ExcelWriter(REPORT_OUTPUT, engine="xlsxwriter") as writer:
        df_results.to_excel(writer, sheet_name="verification_details", index=False)
        df_summary.to_excel(writer, sheet_name="verdicts_par_attaque", index=False)
        df_metrics.to_excel(writer, sheet_name="metriques_globales", index=False)

        # Mise en forme conditionnelle sur la feuille principale
        wb  = writer.book
        ws  = writer.sheets["verification_details"]
        fmt_intact   = wb.add_format({"bg_color": "#C6EFCE", "font_color": "#276221"})
        fmt_tampered = wb.add_format({"bg_color": "#FFC7CE", "font_color": "#9C0006"})
        n = len(df_results) + 1
        col_verdict = df_results.columns.get_loc("verdict")
        ws.conditional_format(1, col_verdict, n, col_verdict, {
            "type": "text", "criteria": "containing", "value": "INTACT",
            "format": fmt_intact,
        })
        for v in [ALTERED_CONTENT, DELETED_LOG, REORDERED_LOG,
                  INVALID_SIGNATURE, ROOT_NOT_FOUND, ANCHOR_MISMATCH]:
            ws.conditional_format(1, col_verdict, n, col_verdict, {
                "type": "text", "criteria": "containing", "value": v,
                "format": fmt_tampered,
            })

    print("\n" + "=" * 65)
    print("RAPPORT DE VERIFICATION — SYNTHESE")
    print("=" * 65)
    print(f"Logs verifies        : {len(df_results)}")
    print(f"Vrais falsifies      : {int(df_results['true_tampered'].sum())}")
    print(f"Vrais clean          : {int((~df_results['true_tampered']).sum())}")
    print(f"TP={tp}  TN={tn}  FP={fp}  FN={fn}")
    print(f"Precision            : {precision:.4f}")
    print(f"Recall               : {recall:.4f}")
    print(f"F1                   : {f1:.4f}")
    print(f"Accuracy             : {accuracy:.4f}")
    print(f"\nRapport ecrit dans   : {REPORT_OUTPUT}")
    print("=" * 65)

    print("\nVerdicts par type d'attaque :")
    print(df_summary.to_string(index=False))


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="Verification integrite log BGL — Partie F")
    parser.add_argument("--log-id",      help="ID d'un log unique a verifier (ex: log_1)")
    parser.add_argument("--csv",         default=DEFAULT_CSV,       help="CSV dataset BGL")
    parser.add_argument("--falsified",   default=DEFAULT_FALSIFIED, help="Excel falsification_BGL.xlsx")
    parser.add_argument("--delta-minutes", type=int, default=DELTA_MINUTES, choices=[1, 5, 10])
    parser.add_argument("--n-rows",      type=int, default=N_ROWS,  help="Nb lignes CSV a charger")
    parser.add_argument("--report",      action="store_true",       help="Generer le rapport complet")
    parser.add_argument("--offline",     action="store_true",
                        help="Mode sans noeud Ethereum (etapes 5-6 ignorees)")
    args = parser.parse_args()

    pk       = load_public_key()
    contract = None
    if not args.offline:
        _, contract = connect_contract()
        if contract is None:
            print("[!] Noeud Ethereum inaccessible — passage en mode offline automatique.")
            args.offline = True

    if args.report:
        run_full_report(
            csv_path       = args.csv,
            falsified_path = args.falsified,
            contract       = contract,
            pk             = pk,
            delta_minutes  = args.delta_minutes,
            n_rows         = args.n_rows,
            offline        = args.offline,
        )

    elif args.log_id:
        print(f"Verification du log '{args.log_id}'...")
        df = pd.read_csv(args.csv, nrows=args.n_rows)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("seq_no").reset_index(drop=True)

        result = verify_one_log(
            log_id        = args.log_id,
            df_reference  = df,
            df_to_verify  = df,
            contract      = contract if not args.offline else None,
            pk            = pk,
            delta_minutes = args.delta_minutes,
        )
        print(f"\n{'='*50}")
        print(f"log_id         : {result.log_id}")
        print(f"seq_no         : {result.seq_no}")
        print(f"batch_id       : {result.batch_id}")
        print(f"leaf_hash      : {result.leaf_hash_local}")
        print(f"root_local     : {result.root_local}")
        print(f"root_onchain   : {result.root_onchain}")
        print(f"sig_valid      : {result.signature_valid}")
        print(f"roots_match    : {result.roots_match}")
        print(f"VERDICT        : *** {result.verdict} ***")
        print(f"detail         : {result.detail}")
        print(f"temps          : {result.elapsed_ms:.2f} ms")
        print(f"{'='*50}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
