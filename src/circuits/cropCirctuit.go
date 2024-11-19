package circuits

import (
	"src/image"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const CropT = 1

type CropCircuit struct {
	PublicKey         eddsa.PublicKey   `gnark:",public"`
	ImageSignature    eddsa.Signature   `gnark:",public"`
	ImageBytes        frontend.Variable // FrImage as a Big Endian
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

func NewCropCircuit(img image.RGBImage, x0, y0, x1, y1 int) (CropCircuit, signature.Signer, signature.PublicKey) {
	digSig, PK, SK := img.Sign() // Sign the image, get the Public and Secret Key

	// Assign the PK & SK to their eddsa equivilant
	var eddsa_digSig eddsa.Signature
	var eddsa_PK eddsa.PublicKey

	eddsa_digSig.Assign(1, digSig)
	eddsa_PK.Assign(1, PK.Bytes())

	// Instantiate a new CropCircuit
	circuit := CropCircuit{
		PublicKey:      eddsa_PK,
		ImageSignature: eddsa_digSig,
		ImageBytes:     img.ToBigEndian(),
		FrImage:        img.ToFrImage(),
		Params: CropParams{
			N:  frontend.Variable(image.N),
			X0: x0,
			Y0: y0,
			X1: x1,
			Y1: y1,
		},
	}

	return circuit, SK, PK
}
