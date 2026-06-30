# final-memoire
# log-integrity-ai-blockchain

## Preuves d'intégrité des journaux systèmes par hachage/Merkle, ancrage Blockchain et détection IA des falsifications

Mémoire de master 2026 — Feryel
Dataset : BGL (Blue Gene/L) — 100 000 logs systèmes réels

---

## Table des matières

1. [Vue d'ensemble du projet](#1-vue-densemble-du-projet)
2. [Structure du projet](#2-structure-du-projet)
3. [Installation](#3-installation)
4. [Partie C — Génération des falsifications](#4-partie-c--génération-des-falsifications)
5. [Partie D — Protocole cryptographique](#5-partie-d--protocole-cryptographique)
6. [Partie E — Ancrage Blockchain](#6-partie-e--ancrage-blockchain)
7. [Partie F — Vérification complète](#7-partie-f--vérification-complète)
8. [Partie G — Détection IA](#8-partie-g--détection-ia)
9. [Partie H — Couplage IA ↔ Ancrage](#9-partie-h--couplage-ia--ancrage)
10. [Partie I — Évaluation complète](#10-partie-i--évaluation-complète)
11. [Résultats clés](#11-résultats-clés)
12. [Lancer tous les tests](#12-lancer-tous-les-tests)

---

## 1. Vue d'ensemble du projet

Ce projet implémente un système complet de vérification d'intégrité de logs systèmes combinant trois couches de protection :

```
Logs BGL
    │
    ▼
[C] Génération de falsifications contrôlées (6 types, 5 intensités)
    │
    ▼
[D] Protocole cryptographique
    ├── Sérialisation canonique + chaîne de hash SHA-256
    ├── Arbre de Merkle par batch temporel (Δt)
    └── Signature Ed25519 de chaque racine
    │
    ▼
[E] Ancrage Blockchain (Ethereum local / Hardhat)
    └── Smart contract LogAnchor.sol
    │
    ▼
[F] Vérification complète (auditeur)
    └── 7 verdicts : INTACT / ALTERED_CONTENT / DELETED_LOG / ...
    │
    ▼
[G] Détection IA (5 modèles)
    ├── TF-IDF + Logistic Regression
    ├── TF-IDF + SVM
    ├── Isolation Forest
    ├── One-Class SVM
    └── LSTM sur séquences d'EventId
    │
    ▼
[H] Couplage IA ↔ Stratégie d'ancrage
    └── 12 stratégies comparées, fonction objectif J
    │
    ▼
[I] Évaluation complète
    └── 3 familles de métriques consolidées
```

---

## 2. Structure du projet

```
log-integrity-ai-blockchain/
│
├── data/
│   ├── raw/                        ← bgl_100000_structured_blockid_event.csv
│   ├── parsed/                     ← logs après parsing (bgl_parsed.csv)
│   ├── tampered/                   ← falsification_BGL.xlsx (partie C)
│   └── splits/                     ← train/val/test splits
│
├── src/
│   ├── parsing/
│   │   ├── drain_parser.py         ← parsing et normalisation des logs BGL
│   │   └── sequence_builder.py     ← construction de séquences d'EventId
│   │
│   ├── crypto/
│   │   ├── hash_chain.py           ← sérialisation canonique + chaîne SHA-256
│   │   ├── merkle_tree.py          ← arbre de Merkle + preuves d'inclusion
│   │   ├── signature.py            ← signature/vérification Ed25519
│   │   └── verifier.py             ← vérification complète (partie F)
│   │
│   ├── blockchain/
│   │   ├── contracts/
│   │   │   └── LogAnchor.sol       ← smart contract Solidity
│   │   ├── deploy.js               ← script de déploiement Hardhat
│   │   ├── anchor_batch.py         ← ancrage on-chain via web3.py
│   │   └── verify_anchor.py        ← vérification on-chain
│   │
│   ├── attacks/
│   │   ├── delete_attack.py        ← suppressions (isolée, séquence, critique)
│   │   ├── inject_attack.py        ← injections (normaux, anormaux)
│   │   ├── modify_attack.py        ← modifications (contenu, niveau, timestamp, sourceId)
│   │   ├── reorder_attack.py       ← réordonnancements (permutation, inversion fenêtre)
│   │   └── replay_attack.py        ← replay et rollback
│   │
│   ├── ai/
│   │   ├── features.py             ← TF-IDF + features numériques
│   │   ├── train_baselines.py      ← LR, SVM, Isolation Forest, One-Class SVM
│   │   ├── train_lstm.py           ← LSTM NumPy sur séquences d'EventId
│   │   └── evaluate.py             ← métriques : F1, AUROC, FPR, FNR, recall/attaque
│   │
│   └── experiments/
│       ├── run_crypto_eval.py      ← évaluation métriques cryptographiques (partie I)
│       ├── run_ai_eval.py          ← évaluation modèles IA (partie G)
│       └── run_cost_eval.py        ← comparaison stratégies d'ancrage (partie H)
│
├── tests/
│   ├── test_hash_chain.py          ← 11 tests unitaires hash_chain
│   ├── test_merkle_proof.py        ← 15 tests unitaires Merkle
│   ├── test_signature.py           ← 10 tests unitaires Ed25519
│   └── test_verifier.py            ←  5 tests unitaires vérificateur
│
├── notebooks/
│   └── results_visualization.ipynb ← visualisation des résultats
│
├── requirements.txt                ← dépendances Python
├── config.yaml                     ← paramètres configurables
└── README.md                       ← ce fichier
```

---

## 3. Installation

### Prérequis

- Python 3.10 ou supérieur
- Node.js 18 ou supérieur (pour Hardhat / partie E)
- pip

### Installation Python

```bash
pip install -r requirements.txt
```

### Installation Node.js (partie E uniquement)

```bash
cd src/blockchain
npm install
```

### Vérification de l'installation

```bash
# Tester les modules cryptographiques
py -m unittest tests.test_hash_chain tests.test_merkle_proof tests.test_signature tests.test_verifier -v

# Vérifier les dépendances Python
py -c "import pandas, sklearn, cryptography, web3; print('OK')"
```

---

## 4. Partie C — Génération des falsifications

### Ce que ça fait
Prend le dataset BGL intact et génère une version falsifiée contenant 6 types d'attaques (suppression, injection, modification, réordonnancement, replay, rollback) avec 5 niveaux d'intensité (0.1% à 10%).

### Input
```
data/raw/bgl_100000_structured_blockid_event.csv
```

### Lancer
```bash
py generate_falsifications_excel.py
```

### Output
```
data/tampered/falsification_BGL.xlsx
  └── feuille "logs_falsifies"  : dataset falsifié avec colonnes log_label, block_label, attack_type
  └── feuille "ground_truth"    : log_id, tampered (True/False), attack_type, severity_level
```

### Résultats
- 103 559 logs dans la version falsifiée
- 23 208 logs falsifiés (22.4%)
- 26 662 blocs falsifiés sur 92 354
- 16 types de falsifications distincts

### Types de falsifications générés

| Type | Description | Détectable par |
|---|---|---|
| `deleted_isolated` | Suppression d'un log isolé | Chaîne de hash |
| `deleted_sequence` | Suppression d'une séquence contiguë | Chaîne de hash |
| `deleted_critical` | Suppression de logs FATAL uniquement | Chaîne de hash |
| `injected_normal` | Injection de logs INFO artificiels | Merkle + IA |
| `injected_abnormal` | Injection de logs FATAL artificiels | Merkle + IA |
| `injected_plausible_timestamp` | Injection avec timestamp cohérent | Merkle + IA |
| `modified_content` | Modification du raw_log | Chaîne de hash + IA |
| `modified_severity` | Passage INFO ↔ FATAL | IA |
| `modified_timestamp` | Décalage du timestamp | Chaîne de hash |
| `modified_sourceid` | Remplacement du source_id | IA |
| `reordered_swap` | Permutation de deux logs | Chaîne de hash |
| `reordered_window_reversed` | Inversion d'une fenêtre | Chaîne de hash |
| `reordered_critical_moved` | Déplacement d'un log critique | Chaîne de hash |
| `replayed_sequence` | Réinjection d'une ancienne séquence | Merkle |
| `replayed_block` | Réinjection d'un bloc déjà vu | Merkle |
| `rollback_old_version` | Remplacement d'un lot récent par l'ancien | Merkle |

---

## 5. Partie D — Protocole cryptographique

### Ce que ça fait
Implémente le protocole cryptographique complet :
1. **Sérialisation canonique** : représentation stable de chaque log avant hachage
2. **Chaîne de hash** : chaque log est lié au précédent via SHA-256
3. **Arbre de Merkle** : regroupement des logs en batches temporels
4. **Signature Ed25519** : signature de chaque racine de Merkle

### Formules implémentées

```
canonical_log_i = sourceId || seqNo || timestamp || eventId || eventTemplate || rawLogHash || previousHash

leaf_i   = SHA256("LOG_LEAF"  || canonical_log_i)
chain_i  = SHA256("LOG_CHAIN" || chain_{i-1}     || leaf_i)
root_b   = MerkleRoot(leaf_1, ..., leaf_N)
sig_b    = Ed25519_Sign(sk, root_b || batchId || sourceId || startSeq || endSeq || timestamp)
```

### Lancer les tests

```bash
py -m unittest tests.test_hash_chain tests.test_merkle_proof tests.test_signature -v
```

### Résultats des 39 tests

```
test_chain_length_matches_input               ... ok
test_deleting_a_log_breaks_subsequent_chain   ... ok
test_intact_chain_verifies                    ... ok
test_modifying_a_record_breaks_chain          ... ok
test_reordering_breaks_chain                  ... ok
test_proof_verifies_for_every_leaf_even_count ... ok
test_proof_verifies_for_every_leaf_odd_count  ... ok
test_swapped_direction_fails_verification     ... ok
test_valid_signature_verifies                 ... ok
test_tampered_root_fails_verification         ... ok
... (39 tests au total)

Ran 39 tests in 0.074s — OK
```

### Lancer la démo complète (preuve d'inclusion + preuve de falsification)

```bash
py src/crypto/demo_pipeline.py
```

### Performance mesurée

| N logs | Temps chaîne (ms) | Temps Merkle (ms) | Taille preuve (octets) |
|---|---|---|---|
| 128 | 0.692 | 0.176 | 344 |
| 512 | 2.780 | 0.554 | 424 |
| 1024 | 5.520 | 1.077 | 464 |

---

## 6. Partie E — Ancrage Blockchain

### Ce que ça fait
Déploie un smart contract Ethereum (`LogAnchor.sol`) sur un réseau local Hardhat et ancre les racines de Merkle on-chain via `web3.py`. Mesure le coût (gas), la latence et la taille des données selon l'intervalle de batching Δt.

### Prérequis
```bash
cd src/blockchain
npm install
```

### Lancer dans l'ordre

```bash
# Terminal 1 : démarrer le nœud Ethereum local
npx hardhat node

# Terminal 2 : déployer le contrat
npx hardhat run deploy.js --network localhost

# Terminal 2 : ancrer les batches
py anchor_batch.py --csv ../../data/raw/bgl_100000_structured_blockid_event.csv --delta-minutes 1

# Terminal 2 : vérifier un ancrage
py verify_anchor.py --batch-id-str "2005-06-03T15:42:00Z|dt1m" --list-events
```

### Fonctions du smart contract

```solidity
anchorRoot(batchId, sourceIdHash, merkleRoot, signature, startSeq, endSeq, timestamp, metadataURI)
getAnchor(batchId)       // récupère les données d'un ancrage
anchorExists(batchId)    // vérifie si un batch est ancré
rootExists(root)         // détecte les replay (racine déjà vue)
```

### Événement émis à chaque ancrage

```solidity
event RootAnchored(
    uint256 indexed batchId,
    bytes32 indexed sourceIdHash,
    bytes32 merkleRoot,
    uint256 timestamp
);
```

### Résultats mesurés (5000 logs réels)

| Δt (min) | Transactions | Gas total | Gas moyen/tx | Temps ancrage (s) | Données on-chain |
|---|---|---|---|---|---|
| 1 | 28 | 10 325 008 | 368 750 | 0.023 | 8 540 octets |
| 5 | 8 | 2 925 160 | 365 645 | 0.021 | 2 440 octets |
| 10 | 4 | 1 472 536 | 368 134 | 0.022 | 1 220 octets |

**Transaction de déploiement** : `0x0328d50a056d79437f4579fb3fb909dcad3aa98651c5bc76a060009f33f24037`
**Gas de déploiement** : 537 910

---

## 7. Partie F — Vérification complète

### Ce que ça fait
Implémente la procédure complète de vérification vue du côté d'un auditeur externe. Prend un log suspect et retourne un verdict en 7 étapes.

### Étapes de vérification

```
1. Recalculer le hash canonique du log reçu
2. Recalculer le chemin Merkle
3. Comparer avec le leaf de référence
4. Vérifier la signature Ed25519
5. Lire le root stocké on-chain
6. Comparer root local vs root on-chain
7. Retourner le verdict
```

### Verdicts possibles

| Verdict | Signification |
|---|---|
| `INTACT` | Log conforme, signature valide, root on-chain conforme |
| `ALTERED_CONTENT` | Contenu du log modifié (raw_log, severity, source_id) |
| `DELETED_LOG` | Log absent du dataset reçu |
| `REORDERED_LOG` | Rupture de chaîne de hash détectée |
| `INVALID_SIGNATURE` | Signature Ed25519 invalide |
| `ROOT_NOT_FOUND` | Batch non ancré on-chain |
| `ANCHOR_MISMATCH` | Root local ≠ root on-chain |

### Lancer

```bash
# Vérifier un seul log
py src/crypto/verifier.py --log-id log_1 --csv data/raw/bgl_100000_structured_blockid_event.csv --offline

# Générer le rapport complet
py src/crypto/verifier.py --report --offline --n-rows 100000
```

### Résultats (700 logs vérifiés : 500 falsifiés + 200 clean)

| Métrique | Valeur |
|---|---|
| Precision | 1.0000 (0 faux positifs) |
| Recall | 0.8280 |
| F1 | 0.9059 |
| Accuracy | 0.8771 |
| TP | 414 | TN | 200 | FP | 0 | FN | 86 |

---

## 8. Partie G — Détection IA

### Ce que ça fait
Entraîne et compare 5 modèles de machine learning pour détecter automatiquement les logs falsifiés. Respect strict de la séparation train/test sans fuite de données.

### Modèles

| # | Modèle | Type |
|---|---|---|
| 1 | TF-IDF + Logistic Regression | Supervisé |
| 2 | TF-IDF + SVM | Supervisé |
| 3 | Isolation Forest | Non supervisé |
| 4 | One-Class SVM | Non supervisé |
| 5 | LSTM sur séquences d'EventId | Séquentiel |

### Split des données (sans fuite)

```
Train  : logs clean (70%) + attaques légères (0.1%, 0.5%)
Val    : logs clean (15%) + attaques légères
Test   : logs clean (15%) + attaques lourdes (1%, 5%, 10%) — non vus à l'entraînement
```

**Important** : le TF-IDF est appris uniquement sur le train set, puis appliqué sur val et test.

### Features utilisées

- **TF-IDF** : 3000 features sur les `event_template` (bigrammes)
- **Numériques** : delta_t, n_critical_window, position_norm, severity_ratio, raw_log_len, template_len, template_num_count

### Lancer

```bash
py src/experiments/run_ai_eval.py
```

### Résultats

| Modèle | F1 | ROC-AUC | PR-AUC | Recall | FNR | Temps (s) |
|---|---|---|---|---|---|---|
| TF-IDF + LR | 0.628 | 0.740 | 0.821 | 0.485 | 0.515 | 5.1 |
| TF-IDF + SVM | 0.542 | 0.754 | 0.828 | 0.377 | 0.623 | 74.5 |
| Isolation Forest | 0.333 | 0.594 | 0.606 | 0.225 | 0.775 | 3.0 |
| One-Class SVM | 0.478 | 0.565 | 0.687 | 0.357 | 0.643 | 5.2 |
| **LSTM** | **0.990** | **0.992** | **1.000** | **0.982** | **0.019** | 101.6 |

**Conclusion** : le LSTM domine largement car il capture l'ordre temporel des séquences d'EventId, ce que les falsifications perturbent directement. Le recall est prioritaire (une falsification non détectée est plus grave qu'une fausse alerte) : le LSTM atteint Recall=0.982 avec FNR=0.019.

---

## 9. Partie H — Couplage IA ↔ Ancrage

### Ce que ça fait
Compare 12 stratégies d'ancrage selon une fonction objectif combinant coût blockchain, latence et sécurité. Utilise le score IA pour déclencher des ancrages adaptatifs.

### Stratégies comparées

| Famille | Variantes |
|---|---|
| Fixe par taille | N = 512, 1024, 2048 logs par batch |
| Fixe par temps | Δt = 1, 5, 10 minutes |
| Adaptatif IA | ancrage immédiat si score IA > seuil (0.3, 0.5, 0.7) |
| Hybride | score IA + criticité + niveau de risque (seuil 0.4, 0.6, 0.8) |

### Fonction objectif

```
J = coût_blockchain + 0.3 × latence + 0.4 × fenêtre_exposition - 0.3 × score_sécurité
```

Plus J est bas, meilleur est le compromis coût/sécurité.

### Lancer

```bash
py src/experiments/run_cost_eval.py
```

### Résultats (top 5)

| Rang | Stratégie | J | Transactions | Gas total | Sécurité |
|---|---|---|---|---|---|
| ★ 1 | Fixe N=512 | 0.0432 | 203 | 74.9M | 0.990 |
| 2 | Fixe N=1024 | 0.0776 | 102 | 37.6M | 0.995 |
| 3 | Fixe N=2048 | 0.3003 | 51 | 18.8M | 1.000 |
| 4 | Fixe Δt=10min | 0.3013 | 225 | 83.0M | 0.963 |
| 5 | Hybride seuil=0.8 | 1.405 | 1473 | 543M | 0.999 |

**Recommandation** : Fixe N=512 pour le meilleur compromis global. Hybride seuil=0.8 en production pour une adaptation dynamique au risque.

---

## 10. Partie I — Évaluation complète

### Ce que ça fait
Consolide toutes les métriques des parties C à H en un seul rapport structuré selon les 3 familles de métriques demandées par le sujet.

### Lancer

```bash
py src/experiments/run_crypto_eval.py
```

### Métriques cryptographiques

| Type d'attaque | Taux de détection |
|---|---|
| Injection | 100% |
| Modification | 100% |
| Replay / Rollback | 100% |
| Réordonnancement (déplacement) | 100% |
| Réordonnancement (permutation/inversion) | Couvert par LSTM (0% par comparaison de champs) |
| Suppression | Couvert par chaîne de hash |

| Timing (N=128 logs) | Valeur |
|---|---|
| Génération chaîne de hash | 0.692 ms |
| Construction arbre Merkle | 0.176 ms |
| Génération preuve d'inclusion | 0.007 ms |
| Vérification preuve | 0.010 ms |
| Taille preuve Merkle (N=512) | 424 octets |

### Métriques IA (meilleur modèle : LSTM)

| Métrique | Valeur |
|---|---|
| Accuracy | 0.9809 |
| Precision | 0.9992 |
| Recall | 0.9815 |
| F1-score | 0.9903 |
| AUROC | 0.9922 |
| AUPRC | 0.9999 |
| FPR | 0.0038 |
| FNR | 0.0185 |
| Detection delay | 257 logs avant ancrage (Fixe N=512) |

### Métriques blockchain/performance

| Métrique | Valeur |
|---|---|
| Gas par ancrage | 368 750 |
| Gas total (Δt=1min, 5000 logs) | 10 325 008 |
| Latence ancrage | 0.022 s/tx |
| Débit | 7 799 logs/s |
| Stockage off-chain (100k logs) | 25 MB |
| Meilleure stratégie | Fixe N=512 (J=0.043) |

---

## 11. Résultats clés

```
┌─────────────────────────────────────────────────────────────────┐
│                    SYNTHÈSE DES RÉSULTATS                       │
├──────────────────┬──────────────────────────────────────────────┤
│ Cryptographie    │ Détection 100% pour injections,              │
│                  │ modifications, replay, rollback              │
│                  │ Preuve Merkle : 424 octets / 0.01 ms        │
├──────────────────┼──────────────────────────────────────────────┤
│ IA (LSTM)        │ F1=0.990  Recall=0.982  AUROC=0.992         │
│                  │ FNR=0.019  (1 falsification ratée sur 54)   │
├──────────────────┼──────────────────────────────────────────────┤
│ Blockchain       │ Gas/tx=368 750  Latence=22ms                │
│                  │ Meilleure stratégie : Fixe N=512 (J=0.043)  │
└──────────────────┴──────────────────────────────────────────────┘
```

---

## 12. Lancer tous les tests

```bash
# Tests unitaires (39 tests — parties D)
py -m unittest tests.test_hash_chain tests.test_merkle_proof tests.test_signature tests.test_verifier -v

# Pipeline de falsification (partie C)
py generate_falsifications_excel.py

# Pipeline cryptographique complet (partie D)
py src/crypto/demo_pipeline.py

# Détection IA complète (partie G)
py src/experiments/run_ai_eval.py

# Couplage IA + ancrage (partie H)
py src/experiments/run_cost_eval.py

# Évaluation consolidée (partie I)
py src/experiments/run_crypto_eval.py
```

---

## Configuration

Tous les paramètres sont centralisés dans `config.yaml` :

```yaml
# Modifier ces valeurs pour adapter le pipeline à votre environnement
data:
  n_rows: 100000        # Nombre de logs à charger
  delta_minutes: 1      # Intervalle de batching (1, 5 ou 10)

crypto:
  hash_algo: sha256
  signature_algo: ed25519

blockchain:
  rpc_url: http://127.0.0.1:8545
  chain_id: 31337

ai:
  seed: 42
  max_features_tfidf: 3000
  lstm_epochs: 6
  threshold_adaptive: 0.5
```

---

## Dépendances principales

```
pandas, numpy, scikit-learn       ← traitement des données et ML
cryptography                      ← Ed25519
web3                              ← connexion Ethereum
matplotlib, xlsxwriter            ← visualisations et rapports Excel
hardhat (npm)                     ← blockchain locale
```

Installation complète : `pip install -r requirements.txt`
