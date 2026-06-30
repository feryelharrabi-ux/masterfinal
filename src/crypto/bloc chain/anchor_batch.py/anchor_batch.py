"""
anchor_batch.py

Calcule la chaine de hash + l'arbre de Merkle + la signature Ed25519 d'un
batch de logs (en reutilisant le module crypto/ deja livre), puis ancre la
racine resultante sur la blockchain Ethereum locale (Hardhat) via
anchorRoot().

Usage :
    python3 anchor_batch.py
    python3 anchor_batch.py --delta-minutes 5
    python3 anchor_batch.py --csv python/sample_logs.csv --delta-minutes 1

Sortie :
    - transaction hash de chaque ancrage
    - gas utilise par transaction
    - temps d'ancrage (latence)
    - taille des donnees envoyees on-chain
    - tableau recapitulatif (cost_report.json + cost_report.csv)
"""

import argparse
import hashlib
import json
import os
import sys
import time

import pandas as pd
from web3 import Web3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))

from crypto.hash_chain import LogRecord, build_chain
from crypto.merkle import group_into_batches, build_merkle_tree
from crypto.signature import (
    BatchSignaturePayload,
    generate_keypair,
    sign_batch,
    private_key_to_bytes,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CSV = os.path.join(SCRIPT_DIR, "python", "sample_logs.csv")
DEPLOYMENT_JSON = os.path.join(SCRIPT_DIR, "deployment.json")
COST_REPORT_JSON = os.path.join(SCRIPT_DIR, "cost_report.json")
COST_REPORT_CSV = os.path.join(SCRIPT_DIR, "cost_report.csv")
KEYS_FILE = os.path.join(SCRIPT_DIR, "signing_key.json")

DEFAULT_RPC_URL = "http://127.0.0.1:8545"


def load_records(csv_path: str, n_rows: int):
    df = pd.read_csv(csv_path, nrows=n_rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("seq_no").reset_index(drop=True)

    records, timestamps = [], []
    for _, row in df.iterrows():
        records.append(LogRecord(
            source_id=str(row["source_id"]),
            seq_no=int(row["seq_no"]),
            timestamp=row["timestamp"].isoformat(),
            event_id=str(row["event_id"]),
            event_template=str(row["event_template"]),
            raw_log=str(row["raw_log"]),
        ))
        timestamps.append(row["timestamp"].to_pydatetime())
    return records, timestamps


def get_or_create_signing_key():
    """Reutilise une cle Ed25519 stockee localement si presente, sinon en
    cree une nouvelle (pour avoir une signature stable entre plusieurs runs
    d'anchor_batch.py / verify_anchor.py)."""
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE) as f:
            data = json.load(f)
        from crypto.signature import private_key_from_bytes
        sk = private_key_from_bytes(bytes.fromhex(data["private_key_hex"]))
        pk = sk.public_key()
        return sk, pk

    sk, pk = generate_keypair()
    from crypto.signature import public_key_to_bytes
    with open(KEYS_FILE, "w") as f:
        json.dump({
            "private_key_hex": private_key_to_bytes(sk).hex(),
            "public_key_hex": public_key_to_bytes(pk).hex(),
        }, f, indent=2)
    return sk, pk


def batch_id_to_uint256(batch_id_str: str) -> int:
    """Convertit le batch_id textuel (ex: '2005-06-03T15:42:00Z|dt1m') en un
    entier uint256 utilisable comme cle du mapping Solidity, via les 32
    octets d'un SHA-256 tronques a 31 octets pour rester < 2**256 sans
    ambiguite de signe (on utilise int.from_bytes en mode unsigned, donc pas
    besoin de tronquer en realite ; SHA-256 produit deja un nombre < 2**256)."""
    digest = hashlib.sha256(batch_id_str.encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder="big")


def source_id_hash_bytes32(source_id: str) -> bytes:
    return hashlib.sha256(source_id.encode("utf-8")).digest()


def connect_web3(rpc_url: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise ConnectionError(
            f"Impossible de se connecter au noeud Ethereum a {rpc_url}.\n"
            f"Demarrez d'abord un noeud Hardhat local : npx hardhat node"
        )
    return w3


def load_deployment():
    if not os.path.exists(DEPLOYMENT_JSON):
        raise FileNotFoundError(
            f"{DEPLOYMENT_JSON} introuvable. Deployez d'abord le contrat : "
            f"npx hardhat run scripts/deploy.js --network localhost"
        )
    with open(DEPLOYMENT_JSON) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="Ancre des batches de logs sur Ethereum local.")
    parser.add_argument("--csv", default=DEFAULT_CSV, help="Chemin du CSV de logs")
    parser.add_argument("--n-rows", type=int, default=300, help="Nombre de logs a charger")
    parser.add_argument("--delta-minutes", type=int, default=1, choices=[1, 5, 10],
                         help="Intervalle de batching Delta_t en minutes")
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL, help="URL du noeud Ethereum")
    parser.add_argument("--metadata-uri", default="", help="URI/CID de metadonnees additionnelles")
    args = parser.parse_args()

    print(f"Connexion au noeud Ethereum : {args.rpc_url}")
    w3 = connect_web3(args.rpc_url)
    deployment = load_deployment()
    contract = w3.eth.contract(address=deployment["address"], abi=deployment["abi"])
    account = w3.eth.accounts[0]
    print(f"Contrat LogAnchor a l'adresse : {deployment['address']}")
    print(f"Compte utilise pour l'ancrage : {account}")

    print(f"\nChargement de {args.n_rows} logs depuis {args.csv}")
    records, timestamps = load_records(args.csv, args.n_rows)
    print(f"{len(records)} logs charges.")

    print("Construction de la chaine de hash...")
    chained = build_chain(records)

    print(f"Regroupement en batches (Delta_t = {args.delta_minutes} min)...")
    batches = group_into_batches(chained, timestamps, delta_minutes=args.delta_minutes)
    print(f"{len(batches)} batches a ancrer.")

    sk, pk = get_or_create_signing_key()

    results = []

    for batch_id_str, items in batches.items():
        leaves = [entry.leaf for entry in items]
        tree = build_merkle_tree(leaves)

        seq_nos = [entry.record.seq_no for entry in items]
        start_seq, end_seq = min(seq_nos), max(seq_nos)
        source_id = items[0].record.source_id
        batch_timestamp = int(timestamps[0].timestamp())

        payload = BatchSignaturePayload(
            root_hex=tree.root_hex,
            batch_id=batch_id_str,
            source_id=source_id,
            start_seq=start_seq,
            end_seq=end_seq,
            timestamp=items[0].record.timestamp,
        )
        signature = sign_batch(sk, payload)

        batch_id_uint = batch_id_to_uint256(batch_id_str)
        source_id_hash = source_id_hash_bytes32(source_id)

        # On encode le timestamp APPLICATIF exact (format ISO utilise pour
        # la signature) dans metadataURI, sous forme JSON, en plus d'un
        # eventuel --metadata-uri fourni par l'utilisateur. Necessaire car
        # le timestamp on-chain (uint256, epoch) seul ne permet pas de
        # reconstruire EXACTEMENT la chaine ISO d'origine (round-trip
        # epoch -> ISO peut differer du format d'origine), ce qui casserait
        # la verification de signature cote verify_anchor.py.
        metadata = {
            "applicative_timestamp_iso": items[0].record.timestamp,
            "user_metadata_uri": args.metadata_uri,
        }
        metadata_uri_value = json.dumps(metadata, separators=(",", ":"))

        # Taille des donnees envoyees on-chain (calldata approximative)
        onchain_payload_size = (
            32 +  # sourceIdHash
            32 +  # merkleRoot
            len(signature) +  # signature
            32 + 32 + 32 +  # startSeq, endSeq, timestamp (uint256 chacun, 32 octets logiques)
            len(metadata_uri_value.encode("utf-8"))
        )

        print(f"\n--- Ancrage du batch '{batch_id_str}' ({len(items)} logs) ---")
        t0 = time.time()
        try:
            tx_hash = contract.functions.anchorRoot(
                batch_id_uint,
                source_id_hash,
                tree.root,
                signature,
                start_seq,
                end_seq,
                batch_timestamp,
                metadata_uri_value,
            ).transact({"from": account})
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            elapsed = time.time() - t0

            print(f"  tx_hash     : {receipt.transactionHash.hex()}")
            print(f"  gas utilise : {receipt.gasUsed}")
            print(f"  temps       : {elapsed:.3f} s")
            print(f"  taille data on-chain (approx) : {onchain_payload_size} octets")

            results.append({
                "batch_id_str": batch_id_str,
                "batch_id_uint": str(batch_id_uint),
                "n_logs": len(items),
                "merkle_root": tree.root_hex,
                "tx_hash": receipt.transactionHash.hex(),
                "gas_used": int(receipt.gasUsed),
                "anchoring_time_seconds": round(elapsed, 4),
                "onchain_payload_size_bytes": onchain_payload_size,
                "status": "success" if receipt.status == 1 else "failed",
            })
        except Exception as e:
            elapsed = time.time() - t0
            print(f"  ECHEC de l'ancrage : {e}")
            results.append({
                "batch_id_str": batch_id_str,
                "batch_id_uint": str(batch_id_uint),
                "n_logs": len(items),
                "merkle_root": tree.root_hex,
                "tx_hash": None,
                "gas_used": None,
                "anchoring_time_seconds": round(elapsed, 4),
                "onchain_payload_size_bytes": onchain_payload_size,
                "status": f"error: {e}",
            })

    # ---- Rapport de cout ----
    df_report = pd.DataFrame(results)
    df_report.to_csv(COST_REPORT_CSV, index=False)
    with open(COST_REPORT_JSON, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("RAPPORT DE COUT")
    print("=" * 70)
    successful = df_report[df_report["status"] == "success"]
    if len(successful):
        print(f"Nombre de transactions          : {len(df_report)}")
        print(f"Nombre de batches (Delta_t={args.delta_minutes}min) : {len(batches)}")
        print(f"Gas moyen par transaction        : {successful['gas_used'].mean():.0f}")
        print(f"Gas total                        : {successful['gas_used'].sum()}")
        print(f"Temps moyen d'ancrage             : {successful['anchoring_time_seconds'].mean():.3f} s")
        print(f"Taille moyenne on-chain (octets)  : {successful['onchain_payload_size_bytes'].mean():.0f}")
    print(f"\nRapport detaille ecrit dans :\n  {COST_REPORT_JSON}\n  {COST_REPORT_CSV}")


if __name__ == "__main__":
    main()
