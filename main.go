package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type MyCircuit struct {
	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

// i know x and y so that x^2 + y = z
func (circuit *MyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Add(api.Mul(circuit.X, circuit.X), circuit.Y), circuit.Z)

	return nil

}

func main() {

	// compile the circuit
	var theCircuit MyCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &theCircuit)
	if err != nil {
		fmt.Println(err)
		return
	}

	// generate witness
	input := &MyCircuit{
		X: 5,
		Y: 6,
		Z: 30,
	}
	witness, _ := frontend.NewWitness(input, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public() // Z
	if err != nil {
		fmt.Printf("ERROR in EXTRACTING PUBLIC WITNESS: %s", err)
		return
	}

	// prove & verify
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("ERROR in SETUP: %s", err)
		return
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("ERROR in PROVE: %s", err)
		return
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("ERROR in VERIFY: %s", err)
		return
	}

	fmt.Println("success!")

}
