"""
verify_anchor.py

Lit les ancrages stockes on-chain et les verifie :
- recupere les donnees via getAnchor(batchId)
- verifie la signature Ed25519 (Verify(pk, signature, message))
- verifie rootExists(root) pour detecter un replay (racine deja ancree sous
  un autre batchId)
- recherche les evenements RootAnchored emis (preuve d'audit independante
  du stockage, utile si on ne connait que la plage de blocs a inspecter)

Usage :
    python3 verify_anchor.py --batch-id-str "2005-06-03T15:42:00Z|dt1m"
    python3 verify_anchor.py --batch-id-str "2005-06-03T15:42:00Z|dt1m" --tamper-root
    python3 verify_anchor.py --list-events
"""

import argparse
import hashlib
import json
import os
import sys

from web3 import Web3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))

from crypto.signature import (
    BatchSignaturePayload,
    public_key_from_bytes,
    verify_batch_signature,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPLOYMENT_JSON = os.path.join(SCRIPT_DIR, "deployment.json")
KEYS_FILE = os.path.join(SCRIPT_DIR, "signing_key.json")
DEFAULT_RPC_URL = "http://127.0.0.1:8545"


def batch_id_to_uint256(batch_id_str: str) -> int:
    digest = hashlib.sha256(batch_id_str.encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder="big")


def load_deployment():
    if not os.path.exists(DEPLOYMENT_JSON):
        raise FileNotFoundError(f"{DEPLOYMENT_JSON} introuvable. Deployez d'abord le contrat.")
    with open(DEPLOYMENT_JSON) as f:
        return json.load(f)


def load_public_key():
    if not os.path.exists(KEYS_FILE):
        raise FileNotFoundError(
            f"{KEYS_FILE} introuvable. Lancez d'abord anchor_batch.py pour generer une cle."
        )
    with open(KEYS_FILE) as f:
        data = json.load(f)
    return public_key_from_bytes(bytes.fromhex(data["public_key_hex"]))


def connect_web3(rpc_url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise ConnectionError(f"Impossible de se connecter au noeud Ethereum a {rpc_url}.")
    return w3


def verify_one_batch(w3, contract, batch_id_str: str, source_id_for_payload: str, tamper_root: bool):
    batch_id_uint = batch_id_to_uint256(batch_id_str)

    print(f"\n--- Verification du batch '{batch_id_str}' (batchId on-chain = {batch_id_uint}) ---")

    exists = contract.functions.anchorExists(batch_id_uint).call()
    print(f"anchorExists(batchId) : {exists}")
    if not exists:
        print("Aucun ancrage trouve pour ce batch_id. Avez-vous lance anchor_batch.py avant ?")
        return

    anchor = contract.functions.getAnchor(batch_id_uint).call()
    (source_id_hash, merkle_root, signature, start_seq, end_seq,
     timestamp, metadata_uri, anchored_at, anchored_by) = anchor

    print(f"sourceIdHash   : 0x{source_id_hash.hex()}")
    print(f"merkleRoot     : 0x{merkle_root.hex()}")
    print(f"startSeq       : {start_seq}")
    print(f"endSeq         : {end_seq}")
    print(f"timestamp      : {timestamp}")
    print(f"metadataURI    : {metadata_uri!r}")
    print(f"anchoredAt(blk): {anchored_at}")
    print(f"anchoredBy     : {anchored_by}")

    root_exists = contract.functions.rootExists(merkle_root).call()
    print(f"rootExists(merkleRoot) : {root_exists}")

    # --- Verification de la signature ---
    # Pour reconstruire le message signe il faut le timestamp APPLICATIF
    # original (sous forme ISO utilisee par crypto.signature au moment de
    # la signature). On utilise ici le timestamp on-chain (unix) converti,
    # ce qui suppose que anchor_batch.py a bien stocke un timestamp
    # coherent avec celui utilise pour signer (c'est le cas dans ce
    # pipeline : voir anchor_batch.py).
    root_hex = merkle_root.hex()
    if tamper_root:
        print("\n[!] --tamper-root actif : on falsifie volontairement le root "
              "utilise pour la verification (simulation d'une preuve frauduleuse).")
        root_hex = "ff" * 32

    # On reconstruit le payload de signature EXACTEMENT comme dans
    # anchor_batch.py : root_hex, batch_id (str original), source_id,
    # start_seq, end_seq, timestamp APPLICATIF (iso). Le timestamp ISO
    # exact est recupere depuis metadataURI (anchor_batch.py l'y stocke en
    # JSON), pour eviter toute perte de precision/format lors d'un
    # round-trip epoch -> ISO qui casserait la verification de signature.
    timestamp_iso = None
    try:
        metadata = json.loads(metadata_uri)
        timestamp_iso = metadata.get("applicative_timestamp_iso")
    except (json.JSONDecodeError, TypeError):
        pass

    if timestamp_iso is None:
        from datetime import datetime, timezone
        timestamp_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        print("[!] Impossible de lire le timestamp ISO exact depuis metadataURI ; "
              "reconstruction approximative depuis l'epoch (peut faire echouer "
              "la verification de signature si le format differe de l'original).")

    payload = BatchSignaturePayload(
        root_hex=root_hex,
        batch_id=batch_id_str,
        source_id=source_id_for_payload,
        start_seq=start_seq,
        end_seq=end_seq,
        timestamp=timestamp_iso,
    )

    try:
        pk = load_public_key()
        sig_valid = verify_batch_signature(pk, bytes(signature), payload)
    except FileNotFoundError as e:
        print(f"\n[!] {e}")
        sig_valid = None

    print(f"\nVerification de la signature Ed25519 : "
          f"{'VALIDE' if sig_valid else 'INVALIDE' if sig_valid is False else 'NON TESTEE'}")

    if exists and root_exists and (sig_valid is True):
        print("\n=> CONCLUSION : ancrage coherent, signature valide, racine "
              "reconnue on-chain. Le batch n'a pas ete falsifie depuis son "
              "ancrage.")
    elif tamper_root:
        print("\n=> CONCLUSION : la signature ne correspond pas a la racine "
              "falsifiee utilisee pour le test : falsification detectee, "
              "comme attendu.")
    else:
        print("\n=> CONCLUSION : anomalie detectee, voir le detail ci-dessus.")


def list_events(w3, contract, from_block=0, to_block="latest"):
    print(f"\n--- Evenements RootAnchored (blocs {from_block} a {to_block}) ---")
    event_filter = contract.events.RootAnchored.create_filter(
        from_block=from_block, to_block=to_block
    )
    events = event_filter.get_all_entries()
    if not events:
        print("Aucun evenement trouve.")
        return
    for ev in events:
        args = ev["args"]
        print(f"  block={ev['blockNumber']} tx={ev['transactionHash'].hex()} "
              f"batchId={args['batchId']} merkleRoot=0x{args['merkleRoot'].hex()} "
              f"timestamp={args['timestamp']}")


def main():
    parser = argparse.ArgumentParser(description="Verifie des ancrages on-chain.")
    parser.add_argument("--batch-id-str", default=None,
                         help="Identifiant textuel du batch (ex: '2005-06-03T15:42:00Z|dt1m')")
    parser.add_argument("--source-id", default="-",
                         help="source_id utilise lors de la signature originale (doit correspondre)")
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--tamper-root", action="store_true",
                         help="Simule une preuve de falsification (root remplace avant verification)")
    parser.add_argument("--list-events", action="store_true",
                         help="Liste tous les evenements RootAnchored emis par le contrat")
    args = parser.parse_args()

    w3 = connect_web3(args.rpc_url)
    deployment = load_deployment()
    contract = w3.eth.contract(address=deployment["address"], abi=deployment["abi"])

    print(f"Contrat LogAnchor a l'adresse : {deployment['address']}")
    print(f"totalAnchors on-chain : {contract.functions.totalAnchors().call()}")

    if args.list_events:
        list_events(w3, contract)

    if args.batch_id_str:
        verify_one_batch(w3, contract, args.batch_id_str, args.source_id, args.tamper_root)
    elif not args.list_events:
        print("\nAucun --batch-id-str fourni. Utilisez --list-events pour voir "
              "les batches ancres, puis relancez avec --batch-id-str '<valeur>'.")


if __name__ == "__main__":
    main()
