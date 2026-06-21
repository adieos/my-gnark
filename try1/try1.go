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

	// START: GET POSEIDON HASH OF A CERTAIN PREIMAGE
	hsh := poseidon2.NewMerkleDamgardHasher()

	var preimage fr.Element
	preimage.SetBigInt(big.NewInt(67))
	hsh.Write(preimage.Marshal())

	digest := hsh.Sum(nil)
	var digestElement fr.Element
	digestElement.SetBytes(digest)
	fmt.Println("Digest:", digestElement.String())
	// END

	// compile the circuit
	var theCircuit circuits.PKCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &theCircuit)
	if err != nil {
		fmt.Println(err)
		return
	}

	// generate witness
	input := &circuits.PKCircuit{
		Preimage: 67,
		Hash:     "20337019135876451277595023879653111205439913965068054979096646526261503550135",
	}
	witness, _ := frontend.NewWitness(input, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public() // hash
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
