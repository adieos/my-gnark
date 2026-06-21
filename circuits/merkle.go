package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// Self implementation. Heavily references my circom version
type MerkleTreeCircuit struct {
	RootHash    frontend.Variable `gnark:",public"`
	PathIndices []frontend.Variable
	Siblings    []frontend.Variable
	Preimage    frontend.Variable
}

func (c *MerkleTreeCircuit) Define(api frontend.API) error {
	// approach 1: use hasher.Reset
	// approach 2: create n hashers, where n = depth

	// i will use approach 1 for now

	hsh, _ := poseidon2.New(api)
	hsh.Write(c.Preimage)
	leaf := hsh.Sum()
	hsh.Reset()

	api.AssertIsEqual(len(c.Siblings), len(c.PathIndices))
	depth := len(c.Siblings)
	currHash := leaf
	for i := 0; i < depth; i++ {
		left := api.Select(c.PathIndices[i], c.Siblings[i], currHash)
		right := api.Select(c.PathIndices[i], currHash, c.Siblings[i])

		hsh.Write(left)
		hsh.Write(right)
		currHash = hsh.Sum()
		hsh.Reset()
	}

	api.AssertIsEqual(c.RootHash, currHash)

	return nil
}

// TO DO: compare with one from gnark/std/accumulator/merkle
