package main

import (
	"fmt"
	"math/big"

	"github.com/adieos/my-gnark/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// preimages
	P1 := 676767
	P2 := 5000
	P3 := "My-Not-So-Long-Salt"
	_ = 6767767676

	hsh := poseidon2.NewMerkleDamgardHasher()
	var ele1 fr.Element
	var ele2 fr.Element
	var ele3 fr.Element
	ele1.SetBigInt(big.NewInt(int64(P1)))
	ele2.SetBigInt(big.NewInt(int64(P2)))
	ele3.SetBytes([]byte(P3))

	hsh.Write(ele1.Marshal())
	hsh.Write(ele2.Marshal())
	hsh.Write(ele3.Marshal())

	resHash := hsh.Sum(nil)

	// compile
	var thecirc circuits.TPKCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &thecirc)
	if err != nil {
		fmt.Printf("ERROR in COMPILE: %s", err)
		return
	}

	// witness construction
	input := &circuits.TPKCircuit{
		P1:   P1,
		P2:   P2,
		P3:   []byte(P3),
		Hash: resHash,
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
