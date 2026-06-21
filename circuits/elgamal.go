package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	twistededwardsgadget "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Elgamal struct {
	Pub_key_X, Pub_key_Y   frontend.Variable
	Msg, Nonce             frontend.Variable
	C1_X, C1_Y, C2_X, C2_Y frontend.Variable `gnark:",public"`
}

// Available Baby Jubjub methods:
// curve.Add(p1, p2 Point) Point                                   // BabyAdd equivalent
// curve.ScalarMul(p1 Point, scalar frontend.Variable) Point       // EscalarMulAny equivalent
// curve.DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point
// curve.AssertIsOnCurve(p1 Point)
// curve.Neg(p1 Point) Point

func (c *Elgamal) Define(api frontend.API) error {
	curve, err := twistededwardsgadget.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return err
	}

	// convert public key to a Point
	pubKey := twistededwardsgadget.Point{
		X: c.Pub_key_X,
		Y: c.Pub_key_Y,
	}

	curve.AssertIsOnCurve(pubKey)

	// get G for baby jubjub
	base := curve.Params().Base
	G := twistededwardsgadget.Point{
		X: base[0],
		Y: base[1],
	}

	// TO DO: validate msg
	// example: msg must be an int less than 50
	api.AssertIsLessOrEqual(c.Msg, 50)

	// get ciphertexts
	C1 := curve.ScalarMul(G, c.Nonce)
	C2 := curve.Add(
		curve.ScalarMul(pubKey, c.Nonce), curve.ScalarMul(G, c.Msg),
	)

	// assert ciphertexts with witness
	api.AssertIsEqual(C1.X, c.C1_X)
	api.AssertIsEqual(C1.Y, c.C1_Y)
	api.AssertIsEqual(C2.X, c.C2_X)
	api.AssertIsEqual(C2.Y, c.C2_Y)

	return nil
}
