// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LogAnchor
/// @notice Ancrage on-chain de racines de Merkle de batches de logs, avec
/// leur signature off-chain (Ed25519, verifiee hors-chaine cote applicatif),
/// pour fournir une preuve d'existence/integrite horodatee et immuable.
///
/// Le contrat ne fait QUE stocker et exposer les donnees d'ancrage : il ne
/// reverifie pas la signature Ed25519 on-chain (EVM ne supporte pas
/// nativement Ed25519 sans precompile/lib couteuse). La verification
/// cryptographique complete (chaine de hash + Merkle + signature) se fait
/// off-chain (modules crypto/ deja livres) ; la blockchain sert de registre
/// d'ancrage public, horodate et infalsifiable pour la racine resultante.
contract LogAnchor {
    /// @notice Une ancre represente un batch de logs dont la racine de
    /// Merkle a ete ancree on-chain.
    struct Anchor {
        bytes32 sourceIdHash;   // hash du sourceId (anonymisation/compacite)
        bytes32 merkleRoot;     // racine de Merkle du batch
        bytes signature;        // signature Ed25519 du root (off-chain), stockee brute (64 octets)
        uint256 startSeq;       // premier seq_no du batch
        uint256 endSeq;         // dernier seq_no du batch
        uint256 timestamp;      // timestamp applicatif du batch (pas block.timestamp)
        string metadataURI;     // URI/CID vers metadonnees additionnelles (ex: IPFS, fichier local)
        uint256 anchoredAt;     // block.timestamp au moment de l'ancrage on-chain
        address anchoredBy;     // msg.sender qui a ancre ce batch
        bool exists;            // flag d'existence (batchId=0 par defaut sinon)
    }

    /// @notice batchId -> Anchor. batchId est un identifiant numerique
    /// unique choisi par l'application (ex: hash tronque ou compteur
    /// derive du batch_id textuel calcule par merkle.py).
    mapping(uint256 => Anchor) private anchors;

    /// @notice Permet de retrouver rapidement si une racine donnee a deja
    /// ete ancree (sans connaitre le batchId), utile pour rootExists().
    mapping(bytes32 => bool) private rootRegistered;

    /// @notice Compteur du nombre total d'ancrages effectues.
    uint256 public totalAnchors;

    event RootAnchored(
        uint256 indexed batchId,
        bytes32 indexed sourceIdHash,
        bytes32 merkleRoot,
        uint256 timestamp
    );

    error AnchorAlreadyExists(uint256 batchId);
    error AnchorDoesNotExist(uint256 batchId);
    error InvalidSequenceRange(uint256 startSeq, uint256 endSeq);
    error EmptyMerkleRoot();

    /// @notice Ancre une nouvelle racine de Merkle pour un batch donne.
    /// @dev Echoue si un ancrage existe deja pour ce batchId (immutabilite :
    /// on n'autorise pas l'ecrasement d'un ancrage existant).
    function anchorRoot(
        uint256 batchId,
        bytes32 sourceIdHash,
        bytes32 merkleRoot,
        bytes calldata signature,
        uint256 startSeq,
        uint256 endSeq,
        uint256 timestamp,
        string calldata metadataURI
    ) external {
        if (anchors[batchId].exists) {
            revert AnchorAlreadyExists(batchId);
        }
        if (merkleRoot == bytes32(0)) {
            revert EmptyMerkleRoot();
        }
        if (endSeq < startSeq) {
            revert InvalidSequenceRange(startSeq, endSeq);
        }

        anchors[batchId] = Anchor({
            sourceIdHash: sourceIdHash,
            merkleRoot: merkleRoot,
            signature: signature,
            startSeq: startSeq,
            endSeq: endSeq,
            timestamp: timestamp,
            metadataURI: metadataURI,
            anchoredAt: block.timestamp,
            anchoredBy: msg.sender,
            exists: true
        });

        rootRegistered[merkleRoot] = true;
        totalAnchors += 1;

        emit RootAnchored(batchId, sourceIdHash, merkleRoot, timestamp);
    }

    /// @notice Recupere les donnees d'ancrage d'un batch donne.
    function getAnchor(uint256 batchId)
        external
        view
        returns (
            bytes32 sourceIdHash,
            bytes32 merkleRoot,
            bytes memory signature,
            uint256 startSeq,
            uint256 endSeq,
            uint256 timestamp,
            string memory metadataURI,
            uint256 anchoredAt,
            address anchoredBy
        )
    {
        Anchor storage a = anchors[batchId];
        if (!a.exists) {
            revert AnchorDoesNotExist(batchId);
        }
        return (
            a.sourceIdHash,
            a.merkleRoot,
            a.signature,
            a.startSeq,
            a.endSeq,
            a.timestamp,
            a.metadataURI,
            a.anchoredAt,
            a.anchoredBy
        );
    }

    /// @notice Indique si un batchId a deja un ancrage.
    function anchorExists(uint256 batchId) external view returns (bool) {
        return anchors[batchId].exists;
    }

    /// @notice Indique si une racine de Merkle donnee a deja ete ancree,
    /// quel que soit le batchId associe. Utile pour detecter un replay
    /// (reinjection d'un batch deja vu) en cherchant si sa racine existe
    /// deja sous un AUTRE batchId.
    function rootExists(bytes32 root) external view returns (bool) {
        return rootRegistered[root];
    }
}
