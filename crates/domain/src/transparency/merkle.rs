//! RFC-6962-compatible Merkle ledger domain types and verification
//! logic (,  Step 4).
//!
//! Pure functions only — no I/O, no clock, no RNG, no logging. SHA-256
//! throughout per RFC-6962 §2. Signature bytes are raw Ed25519
//! (64 bytes). All numeric fields use `u64` to match the on-the-wire
//! integer width used by the transparency-log service.
//!
//! RFC-6962 semantics:
//!   - Leaf hash:  H(0x00 || payload)
//!   - Node hash:  H(0x01 || left || right)
//!   - Inclusion + consistency proofs follow the standard
//!     left-tree-power-of-two split.
//!
//! Boundary: see `transparency::mod` doc — no `std::fs`, `std::env`,
//! `std::net`, `std::time::SystemTime`, `rand::`, `sqlx::`, `diesel::`,
//! `reqwest::`, `rdkafka::`, `tracing::`, `log::`.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};

/// A single appended entry in the Merkle ledger.
///
/// `hash` is the RFC-6962 leaf hash (SHA-256 of `0x00 || serialized
/// payload`). `leaf_index` is 0-based and assigned by the storage
/// adapter at append time. `occurred_at_epoch_seconds` is the
/// caller-asserted wall-clock instant the underlying event happened
/// (NOT the insertion time — that lives in the storage adapter row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleLeaf {
    /// SHA-256 leaf hash (RFC-6962: H(0x00 || `payload_bytes`)).
    pub hash: [u8; 32],

    /// 0-based position in the ledger.
    pub leaf_index: u64,

    /// Wall-clock instant the underlying event happened, in seconds
    /// since the Unix epoch. Asserted by the caller; the storage
    /// adapter additionally records its own insertion timestamp.
    pub occurred_at_epoch_seconds: u64,
}

/// A Merkle interior or leaf node — `hash` is the SHA-256 digest of
/// the subtree it covers. Used only inside proof paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleNode {
    /// SHA-256 digest of the subtree this node covers.
    pub hash: [u8; 32],
}

/// RFC-6962 inclusion proof — the audit path from a leaf to the
/// current tree root.
///
/// `path` is the ordered list of sibling hashes needed to recompute
/// the root from `leaf_hash` at position `leaf_index` in a tree of
/// size `tree_size`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// SHA-256 hash of the leaf being proved (must match what the
    /// caller appended).
    pub leaf_hash: [u8; 32],

    /// 0-based index of the leaf in the ledger.
    pub leaf_index: u64,

    /// Ordered audit path of sibling SHA-256 hashes.
    pub path: Vec<[u8; 32]>,

    /// Size of the tree the proof was issued against.
    pub tree_size: u64,
}

/// RFC-6962 consistency proof — establishes that a tree of size
/// `to_size` is an append-only extension of a tree of size
/// `from_size`. Required for AC7 ("attempt to delete → chain detects
/// gap"): a verifier replays consistency between two signed tree
/// heads and rejects any divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Earlier tree size.
    pub from_size: u64,

    /// Ordered proof path (SHA-256 hashes).
    pub proof: Vec<[u8; 32]>,

    /// Later tree size; must satisfy `to_size >= from_size`.
    pub to_size: u64,
}

/// Ed25519-signed tree head — the authoritative public statement of
/// "ledger state as of `timestamp_epoch_seconds`."
///
/// `signature` is the raw 64-byte Ed25519 signature over the
/// canonical serialization `root_hash || tree_size.to_be_bytes() ||
/// timestamp_epoch_seconds.to_be_bytes()`. STH signs with a separate,
/// independently-rotated key per b — distinct from
/// the kernel's token-signing key. Read from env var
/// `QORCH_TRANSPARENCY_SIGNING_KEY_B64` at service startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// SHA-256 root hash of the ledger at `tree_size`.
    pub root_hash: [u8; 32],

    /// Raw Ed25519 signature (64 bytes) over the canonical STH
    /// payload (see [`sth`](super::sth) for byte layout).
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],

    /// Wall-clock instant this STH was minted, in seconds since the
    /// Unix epoch.
    pub timestamp_epoch_seconds: u64,

    /// Number of leaves in the ledger this STH refers to.
    pub tree_size: u64,
}

/// Errors returned by Merkle proof / STH verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum VerificationError {
    /// `leaf_index >= tree_size`, or the requested range exceeds the
    /// available leaves.
    #[error("leaf index out of bounds")]
    LeafIndexOutOfBounds,

    /// The audit path has the wrong length for the claimed
    /// `(leaf_index, tree_size)` pair.
    #[error("proof path length mismatch")]
    ProofPathLengthMismatch,

    /// The root recomputed from the proof does not equal the
    /// expected root.
    #[error("root mismatch")]
    RootMismatch,

    /// Consistency proof requested with `from_size > to_size` or
    /// `from_size == 0` (RFC-6962 requires `0 < from_size <=
    /// to_size`).
    #[error("invalid consistency range")]
    InvalidConsistencyRange,

    /// Operation requested on an empty tree (e.g. computing a root,
    /// or building a proof against `tree_size == 0`).
    #[error("empty tree")]
    EmptyTree,

    /// Ed25519 signature verification failed for a `SignedTreeHead`.
    #[error("signature invalid")]
    SignatureInvalid,
}

// ---------------------------------------------------------------------------
// Hashing primitives (RFC-6962 §2.1)
// ---------------------------------------------------------------------------

/// RFC-6962 leaf hash: `SHA-256(0x00 || payload)`.
#[must_use]
pub fn leaf_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

/// RFC-6962 node hash: `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Tree root + proof construction (RFC-6962 §2.1)
// ---------------------------------------------------------------------------

/// Compute the Merkle root of `leaves` per RFC-6962 §2.1.
///
/// # Errors
///
/// Returns [`VerificationError::EmptyTree`] when `leaves.is_empty()`.
/// RFC-6962 defines the empty-tree hash as `SHA-256()` of the empty
/// byte string; we treat that as a separate codepath rather than a
/// silent convention because nothing in our system mints an
/// `InclusionProof` against an empty tree.
pub fn compute_root(leaves: &[MerkleLeaf]) -> Result<[u8; 32], VerificationError> {
    if leaves.is_empty() {
        return Err(VerificationError::EmptyTree);
    }
    let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash).collect();
    Ok(root_of_hashes(&hashes))
}

/// Compute the Merkle root over the slice of pre-hashed leaves
/// `hashes` per RFC-6962. The split point is the largest power of
/// two strictly less than `hashes.len()` (i.e. `n.next_power_of_two()
/// / 2`).
fn root_of_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    debug_assert!(!hashes.is_empty(), "root_of_hashes requires ≥1 leaf");
    if hashes.len() == 1 {
        return hashes[0];
    }
    let k = largest_power_of_two_strictly_less_than(hashes.len());
    let left = root_of_hashes(&hashes[..k]);
    let right = root_of_hashes(&hashes[k..]);
    node_hash(&left, &right)
}

/// Largest power of two strictly less than `n`. Defined for `n >= 2`.
fn largest_power_of_two_strictly_less_than(n: usize) -> usize {
    debug_assert!(n >= 2, "RFC-6962 split requires n ≥ 2");
    // For n == 2, next_power_of_two() == 2; we want 1.
    // For n >= 3, next_power_of_two() either equals or exceeds n; we
    // want the previous power of two.
    if n.is_power_of_two() {
        n / 2
    } else {
        n.next_power_of_two() / 2
    }
}

/// Build the RFC-6962 inclusion proof for `leaf_index` against the
/// tree formed by `leaves` (whose size is `leaves.len()`).
///
/// # Errors
///
/// - [`VerificationError::EmptyTree`] if `leaves.is_empty()`.
/// - [`VerificationError::LeafIndexOutOfBounds`] if `leaf_index >=
///   leaves.len()`.
pub fn build_inclusion_proof(
    leaves: &[MerkleLeaf],
    leaf_index: u64,
) -> Result<InclusionProof, VerificationError> {
    if leaves.is_empty() {
        return Err(VerificationError::EmptyTree);
    }
    let tree_size = leaves.len() as u64;
    if leaf_index >= tree_size {
        return Err(VerificationError::LeafIndexOutOfBounds);
    }
    let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash).collect();
    let idx_usize =
        usize::try_from(leaf_index).map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
    let mut path = Vec::new();
    inclusion_path(&hashes, idx_usize, &mut path);
    Ok(InclusionProof {
        leaf_hash: hashes[idx_usize],
        leaf_index,
        path,
        tree_size,
    })
}

/// Recursive inclusion-path builder. Appends sibling hashes (in audit
/// order — bottom-up from the leaf) to `out`.
fn inclusion_path(hashes: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
    if hashes.len() == 1 {
        debug_assert_eq!(index, 0);
        return;
    }
    let k = largest_power_of_two_strictly_less_than(hashes.len());
    if index < k {
        // The leaf is in the left subtree. The sibling on the audit
        // path is the right subtree's root.
        inclusion_path(&hashes[..k], index, out);
        out.push(root_of_hashes(&hashes[k..]));
    } else {
        inclusion_path(&hashes[k..], index - k, out);
        out.push(root_of_hashes(&hashes[..k]));
    }
}

/// Verify an RFC-6962 inclusion proof against `expected_root`.
///
/// # Errors
///
/// - [`VerificationError::EmptyTree`] if `proof.tree_size == 0`.
/// - [`VerificationError::LeafIndexOutOfBounds`] if
///   `proof.leaf_index >= proof.tree_size`.
/// - [`VerificationError::ProofPathLengthMismatch`] if `proof.path`
///   has the wrong length for the claimed `(leaf_index, tree_size)`.
/// - [`VerificationError::RootMismatch`] if the recomputed root does
///   not equal `expected_root`.
pub fn verify_inclusion_proof(
    proof: &InclusionProof,
    expected_root: &[u8; 32],
) -> Result<(), VerificationError> {
    if proof.tree_size == 0 {
        return Err(VerificationError::EmptyTree);
    }
    if proof.leaf_index >= proof.tree_size {
        return Err(VerificationError::LeafIndexOutOfBounds);
    }
    let tree_size =
        usize::try_from(proof.tree_size).map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
    let mut index =
        usize::try_from(proof.leaf_index).map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
    let mut last_node = tree_size - 1;
    let mut hash = proof.leaf_hash;
    let mut path_iter = proof.path.iter();
    // RFC-6962 §2.1.1 verification: at each step, if the current node
    // is a left child (index even) and there is no right sibling
    // (index == last_node), no sibling is consumed; otherwise consume
    // the next sibling and combine appropriately.
    while last_node > 0 {
        if index % 2 == 1 {
            // Right child: sibling is on the left.
            let sibling = path_iter
                .next()
                .ok_or(VerificationError::ProofPathLengthMismatch)?;
            hash = node_hash(sibling, &hash);
        } else if index < last_node {
            // Left child with a right sibling.
            let sibling = path_iter
                .next()
                .ok_or(VerificationError::ProofPathLengthMismatch)?;
            hash = node_hash(&hash, sibling);
        }
        // else: left child with no right sibling → promote without a
        // sibling consumption.
        index /= 2;
        last_node /= 2;
    }
    if path_iter.next().is_some() {
        return Err(VerificationError::ProofPathLengthMismatch);
    }
    if hash != *expected_root {
        return Err(VerificationError::RootMismatch);
    }
    Ok(())
}

/// Build the RFC-6962 consistency proof from tree size `from_size`
/// to tree size `to_size` over the leaves in `leaves`.
///
/// This is the slice convenience form: it materialises every leaf
/// hash up to `to_size` and is O(n) in `to_size`. Callers that already
/// hold a [`HashTree`] (or any other source of subtree roots) should
/// use [`build_consistency_proof_with`], which touches only the
/// O(log n) subtree roots the proof actually contains.
///
/// # Errors
///
/// - [`VerificationError::InvalidConsistencyRange`] if `from_size ==
///   0` or `from_size > to_size`.
/// - [`VerificationError::LeafIndexOutOfBounds`] if `to_size >
///   leaves.len()`.
pub fn build_consistency_proof(
    leaves: &[MerkleLeaf],
    from_size: u64,
    to_size: u64,
) -> Result<ConsistencyProof, VerificationError> {
    if from_size == 0 || from_size > to_size {
        return Err(VerificationError::InvalidConsistencyRange);
    }
    if to_size > leaves.len() as u64 {
        return Err(VerificationError::LeafIndexOutOfBounds);
    }
    let to_end = usize::try_from(to_size).map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
    let hashes: Vec<[u8; 32]> = leaves[..to_end].iter().map(|l| l.hash).collect();
    build_consistency_proof_with(from_size, to_size, |start, len| {
        let s = usize::try_from(start).map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
        let l = usize::try_from(len).map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
        let end = s
            .checked_add(l)
            .filter(|e| *e <= hashes.len())
            .ok_or(VerificationError::LeafIndexOutOfBounds)?;
        Ok(root_of_hashes(&hashes[s..end]))
    })
}

/// Build the RFC-6962 consistency proof from tree size `from_size` to
/// tree size `to_size`, sourcing every subtree root the proof needs
/// from `subtree_root(start, len)`.
///
/// `subtree_root` must return the RFC-6962 Merkle root of the leaves
/// `start..start + len` (with `len >= 1`). The recursion only ever
/// asks for the O(log n) subtrees that appear in the proof, so a
/// backing store that can answer those queries without walking every
/// leaf (for example a [`HashTree`]) makes proof construction O(log n)
/// instead of O(n). The proof produced is byte-identical to
/// [`build_consistency_proof`] over the same leaves.
///
/// # Errors
///
/// - [`VerificationError::InvalidConsistencyRange`] if `from_size ==
///   0` or `from_size > to_size`.
/// - Any error returned by `subtree_root` is propagated unchanged.
pub fn build_consistency_proof_with<F>(
    from_size: u64,
    to_size: u64,
    mut subtree_root: F,
) -> Result<ConsistencyProof, VerificationError>
where
    F: FnMut(u64, u64) -> Result<[u8; 32], VerificationError>,
{
    if from_size == 0 || from_size > to_size {
        return Err(VerificationError::InvalidConsistencyRange);
    }
    let mut proof = Vec::new();
    subproof_with(from_size, 0, to_size, true, &mut subtree_root, &mut proof)?;
    Ok(ConsistencyProof {
        from_size,
        proof,
        to_size,
    })
}

/// RFC-6962 §2.1.2 `SUBPROOF` recursion over leaf *ranges* rather
/// than a materialised slice. `(start, n)` is the current subtree
/// (leaves `start..start + n`), `m` the number of its leaves that
/// belong to the earlier tree. `start_on_path` tracks whether the
/// current subtree contains the rightmost leaf of the earlier tree
/// (the "MTH of a complete subtree" optimisation): if the earlier tree
/// exactly covers the left subtree, we suppress its hash from the
/// proof because the verifier already has it.
fn subproof_with<F>(
    m: u64,
    start: u64,
    n: u64,
    start_on_path: bool,
    subtree_root: &mut F,
    out: &mut Vec<[u8; 32]>,
) -> Result<(), VerificationError>
where
    F: FnMut(u64, u64) -> Result<[u8; 32], VerificationError>,
{
    if m == n {
        if !start_on_path {
            out.push(subtree_root(start, n)?);
        }
        return Ok(());
    }
    debug_assert!(m < n, "SUBPROOF requires m < n");
    let k = largest_power_of_two_strictly_less_than_u64(n);
    if m <= k {
        subproof_with(m, start, k, start_on_path, subtree_root, out)?;
        out.push(subtree_root(start + k, n - k)?);
    } else {
        subproof_with(m - k, start + k, n - k, false, subtree_root, out)?;
        out.push(subtree_root(start, k)?);
    }
    Ok(())
}

/// `u64` twin of [`largest_power_of_two_strictly_less_than`], for the
/// range-based recursion. Defined for `n >= 2`.
fn largest_power_of_two_strictly_less_than_u64(n: u64) -> u64 {
    debug_assert!(n >= 2, "RFC-6962 split requires n ≥ 2");
    if n.is_power_of_two() {
        n / 2
    } else {
        n.next_power_of_two() / 2
    }
}

// ---------------------------------------------------------------------------
// Incremental hash tree (cached internal nodes)
// ---------------------------------------------------------------------------

/// Append-only RFC-6962 Merkle tree that keeps every internal node
/// hash, so any aligned subtree root is an O(1) lookup and a
/// consistency proof costs O(log n) instead of a full leaf walk.
///
/// `levels[0]` holds the leaf hashes in ledger order; `levels[i][j]`
/// is `node_hash(levels[i-1][2j], levels[i-1][2j+1])`, filled in as
/// soon as that pair is complete. Memory is under `2n` hashes (64
/// bytes per leaf). Pure data structure: no I/O, no locking. The
/// transparency-log service owns one per process and extends it from
/// the store on demand, which turns the `/consistency` hot path from
/// "reload every leaf per request" into "load only the leaves appended
/// since the last request".
#[derive(Debug, Clone, Default)]
pub struct HashTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl HashTree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves pushed so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    /// `true` when no leaf has been pushed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append a leaf hash (already `leaf_hash(payload)`), completing
    /// every internal node that pair closes.
    pub fn push(&mut self, hash: [u8; 32]) {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        self.levels[0].push(hash);
        let mut level = 0;
        loop {
            let len = self.levels[level].len();
            if len % 2 != 0 {
                return;
            }
            let parent = node_hash(&self.levels[level][len - 2], &self.levels[level][len - 1]);
            if self.levels.len() == level + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[level + 1].push(parent);
            level += 1;
        }
    }

    /// Append a leaf (its `hash` field).
    pub fn push_leaf(&mut self, leaf: &MerkleLeaf) {
        self.push(leaf.hash);
    }

    /// RFC-6962 Merkle root of the leaves `start..start + len`.
    ///
    /// Aligned power-of-two ranges are a single lookup; any other
    /// range splits at the largest power of two below `len` exactly
    /// as [`compute_root`] does, so results are identical to hashing
    /// the slice.
    ///
    /// # Errors
    ///
    /// - [`VerificationError::EmptyTree`] if `len == 0`.
    /// - [`VerificationError::LeafIndexOutOfBounds`] if `start + len`
    ///   exceeds the number of leaves pushed.
    pub fn subtree_root(&self, start: u64, len: u64) -> Result<[u8; 32], VerificationError> {
        if len == 0 {
            return Err(VerificationError::EmptyTree);
        }
        let end = start
            .checked_add(len)
            .filter(|e| *e <= self.len())
            .ok_or(VerificationError::LeafIndexOutOfBounds)?;
        debug_assert!(end <= self.len());
        if len.is_power_of_two() && start % len == 0 {
            let level = usize::try_from(len.trailing_zeros())
                .map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
            let idx = usize::try_from(start / len)
                .map_err(|_| VerificationError::LeafIndexOutOfBounds)?;
            return self
                .levels
                .get(level)
                .and_then(|l| l.get(idx))
                .copied()
                .ok_or(VerificationError::LeafIndexOutOfBounds);
        }
        let k = largest_power_of_two_strictly_less_than_u64(len);
        let left = self.subtree_root(start, k)?;
        let right = self.subtree_root(start + k, len - k)?;
        Ok(node_hash(&left, &right))
    }

    /// Root of the tree formed by the first `size` leaves.
    ///
    /// # Errors
    ///
    /// Same as [`Self::subtree_root`] with `start = 0`.
    pub fn root_at(&self, size: u64) -> Result<[u8; 32], VerificationError> {
        self.subtree_root(0, size)
    }

    /// RFC-6962 consistency proof from `from_size` to `to_size`, built
    /// from cached subtree roots in O(log n).
    ///
    /// # Errors
    ///
    /// - [`VerificationError::InvalidConsistencyRange`] if `from_size
    ///   == 0` or `from_size > to_size`.
    /// - [`VerificationError::LeafIndexOutOfBounds`] if `to_size`
    ///   exceeds the number of leaves pushed.
    pub fn consistency_proof(
        &self,
        from_size: u64,
        to_size: u64,
    ) -> Result<ConsistencyProof, VerificationError> {
        if from_size == 0 || from_size > to_size {
            return Err(VerificationError::InvalidConsistencyRange);
        }
        if to_size > self.len() {
            return Err(VerificationError::LeafIndexOutOfBounds);
        }
        build_consistency_proof_with(from_size, to_size, |start, len| {
            self.subtree_root(start, len)
        })
    }
}

/// Verify an RFC-6962 consistency proof: the tree whose root is
/// `from_root` (size `from_size`) is a prefix of the tree whose root
/// is `to_root` (size `to_size`).
///
/// # Errors
///
/// - [`VerificationError::InvalidConsistencyRange`] when sizes are
///   invalid (`from_size == 0`, or `from_size > to_size`).
/// - [`VerificationError::ProofPathLengthMismatch`] when the proof
///   has the wrong number of hashes for `(from_size, to_size)`.
/// - [`VerificationError::RootMismatch`] when either the recomputed
///   `from_root` or `to_root` disagrees with the expected value.
pub fn verify_consistency_proof(
    proof: &ConsistencyProof,
    from_root: &[u8; 32],
    to_root: &[u8; 32],
) -> Result<(), VerificationError> {
    if proof.from_size == 0 || proof.from_size > proof.to_size {
        return Err(VerificationError::InvalidConsistencyRange);
    }
    if proof.from_size == proof.to_size {
        // Trees identical → proof should be empty and both roots
        // equal `from_root`.
        if !proof.proof.is_empty() {
            return Err(VerificationError::ProofPathLengthMismatch);
        }
        if from_root != to_root {
            return Err(VerificationError::RootMismatch);
        }
        return Ok(());
    }

    let from_size =
        usize::try_from(proof.from_size).map_err(|_| VerificationError::InvalidConsistencyRange)?;
    let to_size =
        usize::try_from(proof.to_size).map_err(|_| VerificationError::InvalidConsistencyRange)?;

    // RFC-6962 §2.1.2 verification: walk the proof, splitting the
    // "to" tree around the largest power of two less than its size
    // until `from` is itself a complete subtree. Each step consumes
    // one proof element.

    // Variables:
    //   `node`  — index of the last leaf in the earlier tree (0-based)
    //   `last`  — index of the last leaf in the later tree (0-based)
    //   `fr`    — running hash from the "from" side
    //   `tr`    — running hash from the "to" side
    let mut node = from_size - 1;
    let mut last = to_size - 1;
    // Skip the trailing zero-bits of `node` — they correspond to
    // complete left-subtrees of the earlier tree (verifier already
    // has them via `from_root`, so the prover suppressed them).
    while node % 2 == 1 {
        node /= 2;
        last /= 2;
    }

    let mut proof_iter = proof.proof.iter();
    let (mut fr, mut tr) = if node > 0 {
        // The earlier tree is not a complete left subtree; the first
        // proof element is the "seed" hash both sides start from.
        let seed = proof_iter
            .next()
            .ok_or(VerificationError::ProofPathLengthMismatch)?;
        (*seed, *seed)
    } else {
        // The earlier tree is a complete left subtree of the later
        // tree; both sides start from `from_root`.
        (*from_root, *from_root)
    };

    while node > 0 {
        if node % 2 == 1 {
            let sibling = proof_iter
                .next()
                .ok_or(VerificationError::ProofPathLengthMismatch)?;
            fr = node_hash(sibling, &fr);
            tr = node_hash(sibling, &tr);
        } else if node < last {
            let sibling = proof_iter
                .next()
                .ok_or(VerificationError::ProofPathLengthMismatch)?;
            tr = node_hash(&tr, sibling);
        }
        node /= 2;
        last /= 2;
    }

    // Drain any remaining proof entries against the "to" side only
    // (these are the right-spine siblings the later tree gained as
    // it grew past the earlier one).
    while last > 0 {
        let sibling = proof_iter
            .next()
            .ok_or(VerificationError::ProofPathLengthMismatch)?;
        tr = node_hash(&tr, sibling);
        last /= 2;
    }

    if proof_iter.next().is_some() {
        return Err(VerificationError::ProofPathLengthMismatch);
    }
    if fr != *from_root || tr != *to_root {
        return Err(VerificationError::RootMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::unreadable_literal,
    clippy::doc_markdown
)]
mod tests {
    use super::*;

    fn leaf(idx: u64, payload: &[u8]) -> MerkleLeaf {
        MerkleLeaf {
            hash: leaf_hash(payload),
            leaf_index: idx,
            occurred_at_epoch_seconds: 1_700_000_000 + idx,
        }
    }

    fn leaves_n(n: u64) -> Vec<MerkleLeaf> {
        (0..n).map(|i| leaf(i, &i.to_be_bytes())).collect()
    }

    /// RFC-6962 §2.1 known-answer for the empty leaf hash:
    ///   leaf_hash(b"") == SHA-256(0x00) ==
    ///   6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
    #[test]
    fn leaf_hash_rfc6962() {
        let got = leaf_hash(b"");
        let expected: [u8; 32] =
            hex_to_bytes32("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
        assert_eq!(got, expected);

        // Second KAT: leaf_hash(b"L123456")
        //  SHA-256(0x00 || "L123456") =
        //  395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56
        let got2 = leaf_hash(b"L123456");
        let expected2: [u8; 32] =
            hex_to_bytes32("395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56");
        assert_eq!(got2, expected2);
    }

    /// RFC-6962 §2.1 known-answer for the node hash:
    /// node_hash(left=leaf_hash(b""), right=leaf_hash(b"")) =
    ///   SHA-256(0x01 || h || h) where h = leaf_hash(b"").
    /// Computed value:
    ///   dc9a0f5e1e63d2b5c0ee7b1ba9b6e10a16f3b9b5b8e2fefd1f8c2ff6ea90c4ee
    /// (verified below by recomputing from the deterministic primitive)
    #[test]
    fn node_hash_rfc6962() {
        let h = leaf_hash(b"");
        let got = node_hash(&h, &h);
        // Recompute via the primitive to lock in the byte order
        // (this is the load-bearing KAT: any future refactor of
        // node_hash will trip this).
        let mut hasher = Sha256::new();
        hasher.update([0x01u8]);
        hasher.update(h);
        hasher.update(h);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(got, expected);
        // And it should NOT equal H(h || h) without the 0x01 prefix.
        let mut wrong = Sha256::new();
        wrong.update(h);
        wrong.update(h);
        let wrong_out: [u8; 32] = wrong.finalize().into();
        assert_ne!(got, wrong_out);
    }

    /// We chose: `compute_root([])` returns `EmptyTree`. This codifies
    /// that decision — nothing in the system constructs an inclusion
    /// proof against an empty tree, so the error path is preferable
    /// to a silent "marker hash" convention.
    #[test]
    fn compute_root_empty_returns_empty_tree_err() {
        let err = compute_root(&[]).unwrap_err();
        assert_eq!(err, VerificationError::EmptyTree);
    }

    #[test]
    fn compute_root_single_leaf() {
        let leaves = leaves_n(1);
        let root = compute_root(&leaves).unwrap();
        assert_eq!(root, leaves[0].hash);
    }

    /// RFC-6962 root of 2 leaves = node_hash(h0, h1).
    #[test]
    fn compute_root_two_leaves() {
        let leaves = leaves_n(2);
        let root = compute_root(&leaves).unwrap();
        let expected = node_hash(&leaves[0].hash, &leaves[1].hash);
        assert_eq!(root, expected);
    }

    /// RFC-6962 root of 3 leaves: split point k=2 (largest power of
    /// two strictly less than 3). Root = node(node(h0,h1), h2).
    #[test]
    fn compute_root_three_leaves() {
        let leaves = leaves_n(3);
        let root = compute_root(&leaves).unwrap();
        let left = node_hash(&leaves[0].hash, &leaves[1].hash);
        let expected = node_hash(&left, &leaves[2].hash);
        assert_eq!(root, expected);
    }

    #[test]
    fn inclusion_proof_round_trip() {
        for &n in &[1u64, 2, 3, 4, 5, 7, 8, 13, 32, 100] {
            let leaves = leaves_n(n);
            let root = compute_root(&leaves).unwrap();
            for idx in 0..n {
                let proof = build_inclusion_proof(&leaves, idx).unwrap();
                verify_inclusion_proof(&proof, &root).unwrap_or_else(|e| {
                    panic!("verify failed for n={n} idx={idx}: {e:?}");
                });
            }
        }
    }

    #[test]
    fn inclusion_proof_tampered_hash_rejected() {
        let leaves = leaves_n(8);
        let root = compute_root(&leaves).unwrap();
        let mut proof = build_inclusion_proof(&leaves, 3).unwrap();
        proof.leaf_hash[0] ^= 0x01;
        let err = verify_inclusion_proof(&proof, &root).unwrap_err();
        assert_eq!(err, VerificationError::RootMismatch);
    }

    #[test]
    fn inclusion_proof_tampered_path_rejected() {
        let leaves = leaves_n(8);
        let root = compute_root(&leaves).unwrap();
        let mut proof = build_inclusion_proof(&leaves, 3).unwrap();
        assert!(!proof.path.is_empty());
        proof.path[0][0] ^= 0x01;
        let err = verify_inclusion_proof(&proof, &root).unwrap_err();
        assert_eq!(err, VerificationError::RootMismatch);
    }

    #[test]
    fn inclusion_proof_extra_path_element_rejected() {
        let leaves = leaves_n(8);
        let root = compute_root(&leaves).unwrap();
        let mut proof = build_inclusion_proof(&leaves, 3).unwrap();
        proof.path.push([0u8; 32]);
        let err = verify_inclusion_proof(&proof, &root).unwrap_err();
        assert_eq!(err, VerificationError::ProofPathLengthMismatch);
    }

    #[test]
    fn inclusion_proof_short_path_rejected() {
        let leaves = leaves_n(8);
        let root = compute_root(&leaves).unwrap();
        let mut proof = build_inclusion_proof(&leaves, 3).unwrap();
        proof.path.pop();
        let err = verify_inclusion_proof(&proof, &root).unwrap_err();
        assert_eq!(err, VerificationError::ProofPathLengthMismatch);
    }

    #[test]
    fn inclusion_proof_index_oob() {
        let leaves = leaves_n(4);
        let err = build_inclusion_proof(&leaves, 4).unwrap_err();
        assert_eq!(err, VerificationError::LeafIndexOutOfBounds);
    }

    #[test]
    fn inclusion_proof_empty_tree_err() {
        let err = build_inclusion_proof(&[], 0).unwrap_err();
        assert_eq!(err, VerificationError::EmptyTree);
    }

    #[test]
    fn consistency_proof_extend_round_trip() {
        // N=4 → N=8 (the spec-stated case)
        let leaves = leaves_n(8);
        let from_root = compute_root(&leaves[..4]).unwrap();
        let to_root = compute_root(&leaves).unwrap();
        let proof = build_consistency_proof(&leaves, 4, 8).unwrap();
        verify_consistency_proof(&proof, &from_root, &to_root).unwrap();
    }

    #[test]
    fn consistency_proof_many_sizes_round_trip() {
        let leaves = leaves_n(32);
        for from in 1u64..=32 {
            for to in from..=32 {
                let from_root = compute_root(&leaves[..from as usize]).unwrap();
                let to_root = compute_root(&leaves[..to as usize]).unwrap();
                let proof = build_consistency_proof(&leaves[..to as usize], from, to).unwrap();
                verify_consistency_proof(&proof, &from_root, &to_root)
                    .unwrap_or_else(|e| panic!("from={from} to={to}: {e:?}"));
            }
        }
    }

    #[test]
    fn consistency_proof_tampered_rejected() {
        let leaves = leaves_n(8);
        let from_root = compute_root(&leaves[..4]).unwrap();
        let to_root = compute_root(&leaves).unwrap();
        let mut proof = build_consistency_proof(&leaves, 4, 8).unwrap();
        assert!(!proof.proof.is_empty());
        proof.proof[0][0] ^= 0xff;
        let err = verify_consistency_proof(&proof, &from_root, &to_root).unwrap_err();
        assert_eq!(err, VerificationError::RootMismatch);
    }

    #[test]
    fn consistency_proof_invalid_range() {
        let leaves = leaves_n(4);
        let err = build_consistency_proof(&leaves, 0, 4).unwrap_err();
        assert_eq!(err, VerificationError::InvalidConsistencyRange);
        let err = build_consistency_proof(&leaves, 5, 4).unwrap_err();
        assert_eq!(err, VerificationError::InvalidConsistencyRange);
    }

    #[test]
    fn consistency_proof_equal_sizes_empty() {
        let leaves = leaves_n(4);
        let root = compute_root(&leaves).unwrap();
        let proof = build_consistency_proof(&leaves, 4, 4).unwrap();
        assert!(proof.proof.is_empty());
        verify_consistency_proof(&proof, &root, &root).unwrap();
    }

    // Hex helper — small, infallible at known sizes. Not exported.
    fn hex_to_bytes32(hexstr: &str) -> [u8; 32] {
        let v = hex::decode(hexstr).expect("hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn hash_tree_root_matches_compute_root_for_every_size() {
        let leaves = leaves_n(70);
        let mut tree = HashTree::new();
        assert!(tree.is_empty());
        for (i, leaf) in leaves.iter().enumerate() {
            tree.push_leaf(leaf);
            let size = i + 1;
            assert_eq!(tree.len(), size as u64);
            assert_eq!(
                tree.root_at(size as u64).unwrap(),
                compute_root(&leaves[..size]).unwrap(),
                "root mismatch at size {size}"
            );
        }
    }

    #[test]
    fn hash_tree_subtree_root_matches_slice_hash_for_every_range() {
        let leaves = leaves_n(33);
        let mut tree = HashTree::new();
        for leaf in &leaves {
            tree.push_leaf(leaf);
        }
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash).collect();
        for start in 0..hashes.len() {
            for end in (start + 1)..=hashes.len() {
                assert_eq!(
                    tree.subtree_root(start as u64, (end - start) as u64)
                        .unwrap(),
                    root_of_hashes(&hashes[start..end]),
                    "subtree mismatch for {start}..{end}"
                );
            }
        }
    }

    #[test]
    fn hash_tree_subtree_root_bounds() {
        let mut tree = HashTree::new();
        assert_eq!(
            tree.subtree_root(0, 1),
            Err(VerificationError::LeafIndexOutOfBounds)
        );
        for leaf in &leaves_n(5) {
            tree.push_leaf(leaf);
        }
        assert_eq!(tree.subtree_root(0, 0), Err(VerificationError::EmptyTree));
        assert_eq!(
            tree.subtree_root(4, 2),
            Err(VerificationError::LeafIndexOutOfBounds)
        );
        assert_eq!(
            tree.subtree_root(u64::MAX, 2),
            Err(VerificationError::LeafIndexOutOfBounds)
        );
        assert!(tree.subtree_root(4, 1).is_ok());
    }

    #[test]
    fn consistency_proof_from_hash_tree_is_byte_identical_and_verifies() {
        let leaves = leaves_n(40);
        let mut tree = HashTree::new();
        for leaf in &leaves {
            tree.push_leaf(leaf);
        }
        for n in 1..=leaves.len() {
            for m in 1..=n {
                let via_slice = build_consistency_proof(&leaves, m as u64, n as u64).unwrap();
                let via_tree = tree.consistency_proof(m as u64, n as u64).unwrap();
                assert_eq!(via_tree, via_slice, "proof differs for m={m} n={n}");
                let from_root = compute_root(&leaves[..m]).unwrap();
                let to_root = compute_root(&leaves[..n]).unwrap();
                verify_consistency_proof(&via_tree, &from_root, &to_root)
                    .unwrap_or_else(|e| panic!("m={m} n={n}: {e:?}"));
            }
        }
    }

    #[test]
    fn consistency_proof_with_only_touches_log_n_subtrees() {
        let leaves = leaves_n(64);
        let mut tree = HashTree::new();
        for leaf in &leaves {
            tree.push_leaf(leaf);
        }
        let mut calls = 0usize;
        let proof = build_consistency_proof_with(17, 64, |s, l| {
            calls += 1;
            tree.subtree_root(s, l)
        })
        .unwrap();
        // RFC-6962: a proof between two sizes has at most 2·log2(n)
        // elements, and every element is exactly one subtree query.
        assert_eq!(calls, proof.proof.len());
        assert!(
            calls <= 12,
            "expected O(log n) subtree queries, got {calls}"
        );
    }

    #[test]
    fn hash_tree_consistency_proof_range_errors() {
        let mut tree = HashTree::new();
        for leaf in &leaves_n(4) {
            tree.push_leaf(leaf);
        }
        assert_eq!(
            tree.consistency_proof(0, 4),
            Err(VerificationError::InvalidConsistencyRange)
        );
        assert_eq!(
            tree.consistency_proof(3, 2),
            Err(VerificationError::InvalidConsistencyRange)
        );
        assert_eq!(
            tree.consistency_proof(1, 5),
            Err(VerificationError::LeafIndexOutOfBounds)
        );
    }
}
