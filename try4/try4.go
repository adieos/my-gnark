package main

import (
	"fmt"

	"github.com/adieos/my-gnark/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// tree builder exists in ai/build_tree.go

func main() {
	// compile. NOTE: since depth MUST be known at compile time, the compiling step is a little different than try1-3.go

	depth := 5
	thecirc := &circuits.MerkleTreeCircuit{
		Siblings:    make([]frontend.Variable, depth),
		PathIndices: make([]frontend.Variable, depth),
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, thecirc)
	if err != nil {
		fmt.Printf("ERROR in COMPILE: %s", err)
		return
	}

	// witness construction
	input := &circuits.MerkleTreeCircuit{
		RootHash:    "2600694203049456029153528685606667720115525908863501813493998226729125324159",
		Siblings:    []frontend.Variable{"8962809502634898116671291998121314430499719778677998893991315383823984379208", "16737074806259107641876877012866276832305113604844986845330674984491803806207", "3526548106793486450661765659668605105997457366321528298042175401935354173868", "9980714624524965907627809343444511245872571960456701356373474978856840246363", "17458039795110777581059752742129494783903982548611469006943154343000327600148"},
		PathIndices: []frontend.Variable{1, 1, 0, 0, 0},
		Preimage:    4,
	}
	witness, err := frontend.NewWitness(input, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("ERROR in BUILDING WITNESS: %s", err)
		return
	}
	pubWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("ERROR in PUB WITNESS: %s", err)
		return
	}

	// prove & verify
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("ERROR in PK VK GEN: %s", err)
		return
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("ERROR in PROVE: %s", err)
		return
	}

	err = groth16.Verify(proof, vk, pubWitness)
	if err != nil {
		fmt.Printf("ERROR in VERIFY: %s", err)
		return
	}

	fmt.Println("Success")

}
