package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// Preimage Knowledge Circuit. try1.go
type PKCircuit struct {
	Hash     frontend.Variable `gnark:",public"`
	Preimage frontend.Variable
}

func (circuit *PKCircuit) Define(api frontend.API) error {
	hasher, _ := poseidon2.New(api)
	hasher.Write(circuit.Preimage)
	api.AssertIsEqual(circuit.Hash, hasher.Sum())

	return nil
}

// Triple Preimage Knowledge Circuit. try2.go
type TPKCircuit struct {
	Hash frontend.Variable `gnark:",public"`
	P1   frontend.Variable
	P2   frontend.Variable
	P3   frontend.Variable
}

func (circuit *TPKCircuit) Define(api frontend.API) error {
	hasher, _ := poseidon2.New(api)
	hasher.Write(circuit.P1)
	hasher.Write(circuit.P2)
	hasher.Write(circuit.P3)
	api.AssertIsEqual(circuit.Hash, hasher.Sum())

	return nil
}

// Triple MiMC Preimage Knowledge Circuit. try3.go
type TMPKCircuit struct {
	Hash frontend.Variable `gnark:",public"`
	P1   frontend.Variable
	P2   frontend.Variable
	P3   frontend.Variable
}

func (c *TMPKCircuit) Define(api frontend.API) error {
	hsh, _ := mimc.New(api)

	hsh.Write(c.P1)
	hsh.Write(c.P2)
	hsh.Write(c.P3)
	api.AssertIsEqual(c.Hash, hsh.Sum())

	return nil
}
