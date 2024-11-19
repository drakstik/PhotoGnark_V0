package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

func (circuit *CropCircuit) VerifySignature(api frontend.API) error {
	// Create a new Twisted Edwards Curve
	edCurve, err := twistededwards.NewEdCurve(api, 1)
	if err != nil {
		return err
	}

	// Create the MiMC hash function for Gnark circuits
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Verify the signature against the Image bytes,
	// using the public key, twisted edwards curve and hash function
	eddsa.Verify(edCurve, circuit.ImageSignature, circuit.ImageBytes, circuit.PublicKey, &mimc)

	return nil
}
