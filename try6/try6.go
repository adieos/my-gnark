package main

import (
	"fmt"

	"github.com/adieos/my-gnark/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {

	// compile the circuit
	var theCircuit circuits.VoteValidity
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &theCircuit)
	if err != nil {
		fmt.Println(err)
		return
	}

	// generate witness
	input := &circuits.VoteValidity{
		V1: 0,
		V2: 1,
		V3: 0,
	}
	witness, _ := frontend.NewWitness(input, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
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
