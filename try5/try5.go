package main

import (
	"fmt"
	"math/big"

	"github.com/adieos/my-gnark/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	x := big.NewInt(600) // secret key
	curve := twistededwards.GetEdwardsCurve()
	G := curve.Base

	// get public key, H = G ^ x
	var pubKey twistededwards.PointAffine
	pubKey.ScalarMultiplication(&G, x)

	// get msg & nonce
	var msg, nonce fr.Element
	NONCE := big.NewInt(676767)
	MSG := big.NewInt(40)
	msg.SetBigInt(MSG)
	nonce.SetBigInt(NONCE)

	// get ciphertexts
	var C1, C2, left, right twistededwards.PointAffine
	C1.ScalarMultiplication(&G, NONCE)
	C2.Add(left.ScalarMultiplication(&pubKey, NONCE), right.ScalarMultiplication(&G, MSG))

	input := &circuits.Elgamal{
		Pub_key_X: pubKey.X,
		Pub_key_Y: pubKey.Y,
		Msg:       msg,
		Nonce:     nonce,
		C1_X:      C1.X,
		C1_Y:      C1.Y,
		C2_X:      C2.X,
		C2_Y:      C2.Y,
	}

	// compile
	var thecirc circuits.Elgamal
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &thecirc)
	if err != nil {
		fmt.Printf("ERROR in COMPILE: %s", err)
		return
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

	// try deciphering it
	var helper twistededwards.PointAffine
	helper.ScalarMultiplication(&C1, x)
	var neghelper twistededwards.PointAffine
	neghelper.Neg(&helper)

	negatedHelper := twistededwards.PointAffine{
		X: neghelper.X,
		Y: helper.Y,
	}

	// plaintext (G^m)
	var P twistededwards.PointAffine
	P.Add(&C2, &negatedHelper)
	var compare twistededwards.PointAffine
	compare.ScalarMultiplication(&G, MSG)

	if P == compare {
		fmt.Println("Comparisaon SUCCESS")
	} else {
		fmt.Println("FAIL DECIPHER")
		fmt.Printf("%x\n", P)
		fmt.Printf("%x", compare)
	}

}
