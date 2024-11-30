package circuits

import (
	"src/image"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// This circuit allows Identity transformation only.
// It only be used to prove & verify that Image_B is the same as  has not been tempered with.
type IdentityCircuit struct {
	PublicKey       eddsa.PublicKey   `gnark:",public"`
	EdDSA_Signature eddsa.Signature   `gnark:",public"`
	ImageBytes      frontend.Variable // FrImage as a Big Endian
	FrImage_A       image.FrImage
	FrImage_B       image.FrImage
}

func (circuit *IdentityCircuit) Define(api frontend.API) error {
	circuit.VerifySignature(api)

	return nil
}

func (circuit *IdentityCircuit) VerifySignature(api frontend.API) error {
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
	eddsa.Verify(edCurve, circuit.EdDSA_Signature, circuit.ImageBytes, circuit.PublicKey, &mimc)

	return nil
}
