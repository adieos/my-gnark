// build_tree.go
// Builds a depth-5 Merkle tree using Poseidon2, matching MerkleTreeCircuit's
// hashing structure exactly:
//
//	leaf  = Poseidon2(Preimage)          (single input  -> matches hsh.Write(c.Preimage); hsh.Sum())
//	node  = Poseidon2(left, right)       (two inputs    -> matches the in-circuit nodeSum pattern)
//
// Path convention (matches gnark's own std/accumulator/merkle, and your circom circuit):
//
//	pathIndices[i] == 1  ->  current node is the RIGHT child at level i  (left=sibling, right=current)
//	pathIndices[i] == 0  ->  current node is the LEFT  child at level i  (left=current, right=sibling)
package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// hashOne computes Poseidon2(x) - matches the circuit's leaf-hashing step.
func hashOne(x fr.Element) fr.Element {
	h := poseidon2.NewMerkleDamgardHasher() // fresh hasher -> no leftover state
	h.Write(x.Marshal())
	digest := h.Sum(nil)

	var out fr.Element
	out.SetBytes(digest)
	return out
}

// hashTwo computes Poseidon2(left, right) - matches the in-circuit nodeSum step.
func hashTwo(left, right fr.Element) fr.Element {
	h := poseidon2.NewMerkleDamgardHasher() // fresh hasher each call - avoids state carryover
	h.Write(left.Marshal())
	h.Write(right.Marshal())
	digest := h.Sum(nil)

	var out fr.Element
	out.SetBytes(digest)
	return out
}

func main() {
	const depth = 5
	const numLeaves = 1 << depth // 32

	// --- 1. example raw preimages, one per leaf ---
	// Replace with your real data later; placeholders are just 1..32 here.
	preimages := make([]fr.Element, numLeaves)
	for i := 0; i < numLeaves; i++ {
		preimages[i].SetBigInt(big.NewInt(int64(i + 1)))
	}

	// --- 2. leaf hashes = Poseidon2(preimage_i) ---
	level := make([]fr.Element, numLeaves)
	for i, p := range preimages {
		level[i] = hashOne(p)
	}

	// --- 3. build the tree level by level ---
	levels := [][]fr.Element{level}
	for len(level) > 1 {
		next := make([]fr.Element, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = hashTwo(level[i], level[i+1])
		}
		levels = append(levels, next)
		level = next
	}
	root := level[0]

	// --- 4. pick a leaf to prove membership for ---
	leafIndex := 3 // change this to test other leaves
	leafPreimage := preimages[leafIndex]

	// --- 5. walk up collecting siblings + path bits ---
	siblings := make([]fr.Element, depth)
	pathIndices := make([]int, depth)
	idx := leafIndex
	for d := 0; d < depth; d++ {
		isRight := idx % 2
		siblingIdx := idx - 1
		if isRight == 0 {
			siblingIdx = idx + 1
		}
		siblings[d] = levels[d][siblingIdx]
		pathIndices[d] = isRight
		idx /= 2
	}

	// --- 6. sanity check: recompute the root using ONLY leaf + siblings + path ---
	cur := hashOne(leafPreimage)
	for d := 0; d < depth; d++ {
		if pathIndices[d] == 1 {
			cur = hashTwo(siblings[d], cur) // current is the right child
		} else {
			cur = hashTwo(cur, siblings[d]) // current is the left child
		}
	}

	if cur.String() != root.String() {
		fmt.Println("❌ MISMATCH - tree construction is inconsistent with the proof")
		fmt.Println("expected:  ", root.String())
		fmt.Println("recomputed:", cur.String())
		return
	}

	// --- 7. print everything ready to paste into a gnark witness assignment ---
	fmt.Println("✅ root reconstructed correctly")
	fmt.Println("RootHash:", root.String())
	fmt.Println("Preimage:", leafPreimage.String())

	fmt.Print("Siblings: []frontend.Variable{")
	for i, s := range siblings {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("\"%s\"", s.String())
	}
	fmt.Println("}")

	fmt.Print("PathIndices: []frontend.Variable{")
	for i, p := range pathIndices {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("%d", p)
	}
	fmt.Println("}")
}
