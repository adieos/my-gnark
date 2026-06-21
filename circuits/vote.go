package circuits

import (
	"github.com/consensys/gnark/frontend"
)

type VoteValidity struct {
	V1, V2, V3 frontend.Variable // add as many vote candidates as needed
}

func (c *VoteValidity) Define(api frontend.API) error {
	// valid if and only if:
	// 1. only 1 vote can be casted
	// 2. each vote is either 0 or 1

	// 1. only 1 vote can be casted
	total := api.Add(c.V1, c.V2, c.V3) // all candidates
	api.AssertIsEqual(total, 1)

	// 2. each vote is either 0 or 1
	api.AssertIsEqual(api.Mul(c.V1, api.Sub(1, c.V1)), 0)
	api.AssertIsEqual(api.Mul(c.V2, api.Sub(1, c.V2)), 0)
	api.AssertIsEqual(api.Mul(c.V3, api.Sub(1, c.V3)), 0)

	return nil
}
