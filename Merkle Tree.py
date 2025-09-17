"""
Noah Kelly
Lecture 4A Homework
Design: Merkle tree for 1 million files
"""

import hashlib
import math

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def next_pow_of_two(n: int) -> int:
    if n <= 0:
        return 1
    return 1 << (n - 1).bit_length()

def build_merkle_tree(leaves: list[bytes]) -> tuple[list[list[str]], str]:
    if not leaves:
        raise ValueError("Need at least one leaf")

    # Hash leaves
    level = [sha256(b) for b in leaves]

    # Pad to next power of two by repeating last element
    target = next_pow_of_two(len(level))
    while len(level) < target:
        level.append(level[-1])

    tree = [level]  # level 0 = leaves
    while len(level) > 1:
        new_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1]
            parent_hash = sha256((left + right).encode())  # Concatenating hex strings
            new_level.append(parent_hash)
        tree.append(new_level)
        level = new_level
    root = tree[-1][0]
    return tree, root

def get_proof(tree: list[list[str]], index: int) -> list[tuple[str, str]]:
    proof = []
    idx = index
    for level in tree[:-1]:  # Stop before root level
        # Ensure index within this level
        if idx % 2 == 0:
            sibling_idx = idx + 1
            pos = 'R'
        else:
            sibling_idx = idx - 1
            pos = 'L'
        # Sibling may exist since the algo padded to a power of two
        sibling_hash = level[sibling_idx]
        proof.append((sibling_hash, pos))
        idx //= 2
    return proof

def verify_proof(leaf: bytes, proof: list[tuple[str, str]], root: str) -> bool:
    current = sha256(leaf)
    for sibling_hash, pos in proof:
        if pos == 'R':
            current = sha256((current + sibling_hash).encode())
        else:
            current = sha256((sibling_hash + current).encode())
    return current == root

# Driver code
files = [
    b"file 0 contents: hello",
    b"file 1 contents: world",
    b"file 2 contents: merkle",
    b"file 3 contents: tree",
    b"file 4 contents: example",
]

tree, root = build_merkle_tree(files)
print("Merkle root:", root)
# Produce proof for leaf index 2 (third file)
idx = 2
proof = get_proof(tree, idx)
print(f"Proof for leaf {idx}:")
for s, pos in proof:
    print("  ", pos, s)
ok = verify_proof(files[idx], proof, root)
print("Proof verification result:", ok)

# Stats
n_files = 1_000_000
padded_leaves = next_pow_of_two(n_files)
tree_nodes = 2 * padded_leaves - 1
approx_bytes = tree_nodes * 32  # SHA-256 = 32 bytes per node
print()
print(f"If you used {n_files:,} files, padded to {padded_leaves:,} leaves.")
print(f"Total nodes approximately equals {tree_nodes:,}; hash storage ≈ {approx_bytes / (1024*1024):.2f} MB")