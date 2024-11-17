package circuits

import (
	"src/image"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type CropCircuit struct {
	PublicKey         eddsa.PublicKey `gnark:",public"`
	ImageSignature    eddsa.Signature `gnark:",public"`
	ImageBytes        frontend.Variable
	FrImage           image.FrImage
	Transformed_Image image.FrImage
	Params            CropParams
}

type CropParams struct {
	N  frontend.Variable
	X0 frontend.Variable
	Y0 frontend.Variable
	X1 frontend.Variable
	Y1 frontend.Variable
}

type Fr_SquareArea struct {
	topLeft     Fr_Location
	bottomRight Fr_Location
}

type Fr_Location struct {
	X frontend.Variable
	Y frontend.Variable
}

func (circuit *CropCircuit) Define(api frontend.API) error {

	circuit.VerifySignature(api)

	return nil
}

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
