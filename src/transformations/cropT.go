package transformations

import (
	"fmt"
	"math/big"
	"src/circuits"
	"src/image"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type CropT struct {
	N  int
	X0 int
	Y0 int
	X1 int
	Y1 int
}

func (t CropT) Transform(img image.Image) (image.Image, error) {
	// Check that image has metadata
	if img.Metadata == nil {
		return image.Image{}, fmt.Errorf("IMAGE METADATA IS NIL")
	}

	// Retrieve image's actual width & height from the metadata
	width, widthOk := img.Metadata["width"].(int)
	height, heightOk := img.Metadata["height"].(int)

	// Check that width and height values are valid from the Metadata map
	if !widthOk || !heightOk {
		return image.Image{}, fmt.Errorf("INVALID IMAGE WIDHT/HEIGHT IN METADATA")
	}

	// Check that the crop boundaries are within th image dimensions
	if t.X0 < 0 || t.Y0 < 0 || t.X1 >= width || t.Y1 >= height || t.X0 > t.X1 || t.Y0 > t.Y1 {
		fmt.Println(t.X0, t.Y0, t.X1, t.Y1)
		return image.Image{}, fmt.Errorf("INVALID CROP DIMENSIONS: OUT OF N*N BOUNDS")
	}

	// Initialize the cropped image to be outputed
	img_cropped, err := image.NewImage("black")
	if err != nil {
		fmt.Println("Error while creating new image: " + err.Error())
	}

	// For each pixel
	for row := 0; row < image.N; row++ {
		for col := 0; col < image.N; col++ {
			// Get the current flat index
			currentIdx := row*image.N + col

			/* Determine which pixel index would be shifted to the current flat index */

			// Get the target index from the current index
			targetIdx := currentIdx + t.X0 + (image.N * t.Y0)

			// Calculate target Row and Col from the target index
			targetRow := targetIdx / image.N
			targetCol := targetIdx % image.N

			// If target Col and Row are within Crop Area
			if targetCol >= t.X0 && targetRow >= t.Y0 && targetCol <= t.X1 && targetRow <= t.Y1 {
				// Set current pixel to target pixel
				img_cropped.Pixels[currentIdx] = img.Pixels[targetIdx]
			} // else the pixel remains black.
		}
	}

	cropWidth := t.X0 - t.X1 + 1
	cropHeight := t.Y0 - t.Y1 + 1

	// Update the metadata to reflect the new width & height of the cropped area
	img_cropped.Metadata["width"] = cropWidth
	img_cropped.Metadata["height"] = cropHeight

	return img_cropped, nil
}

func (t CropT) GetType() string {
	return "crop"
}

func (t CropT) NewCircuit(img image.Image, croppedImage image.Image, secretKey signature.Signer) (circuits.CropCircuit, error) {
	digSig := img.Sign(secretKey) // Sign the image, get the Public and Secret Key

	// Assign the PK & SK to their eddsa equivilant
	var eddsa_digSig eddsa.Signature
	var eddsa_PK eddsa.PublicKey

	pk := secretKey.Public()

	eddsa_digSig.Assign(1, digSig)
	eddsa_PK.Assign(1, pk.Bytes())

	// Access ChildStruct fields
	// Instantiate a new CropCircuit
	circuit := circuits.CropCircuit{
		PublicKey:         eddsa_PK,
		EdDSA_Signature:   eddsa_digSig,
		ImageBytes:        img.ToBigEndian(),
		FrImage:           img.ToFrImage(),
		Transformed_Image: croppedImage.ToFrImage(),
		Params: circuits.FrCropT{
			N:  frontend.Variable(t.N),
			X0: frontend.Variable(t.X0),
			Y0: frontend.Variable(t.Y0),
			X1: frontend.Variable(t.X1),
			Y1: frontend.Variable(t.Y1),
		},
	}

	return circuit, nil
}

func (t CropT) TransformAndProve(proving_key groth16.ProvingKey, secretKey signature.Signer, img image.Image, proof_in circuits.Proof, security_parameter *big.Int) (circuits.Proof, image.Image, error) {
	// Transform the image
	croppedImage, err := t.Transform(img)
	if err != nil {
		return circuits.Proof{}, image.Image{}, err
	}

	// Create a new IdentityCircuit struct using the image_in and a secret key
	circuit, err := t.NewCircuit(img, croppedImage, secretKey)
	if err != nil {
		return circuits.Proof{}, image.Image{}, err
	}

	// Create the secret witness from the circuit
	secret_witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		return circuits.Proof{}, image.Image{}, err
	}

	// Set the security parameter and compile a constraint system (aka compliance_predicate)
	compliance_predicate, err := frontend.Compile(security_parameter, r1cs.NewBuilder, &circuits.CropCircuit{})
	if err != nil {
		return circuits.Proof{}, image.Image{}, err
	}

	// Prove the secret witness adheres to the compliance predicate, using the given proving key
	pcd_proof, err := groth16.Prove(compliance_predicate, proving_key, secret_witness)
	if err != nil {
		return circuits.Proof{}, image.Image{}, err
	}

	// Create a public witness
	publicWitness, err := secret_witness.Public()
	if err != nil {
		return circuits.Proof{}, image.Image{}, err
	}

	proof := circuits.Proof{PCD_Proof: pcd_proof, Signature: proof_in.Signature, Public_Witness: publicWitness}
	// Return the proof, image, signature and public witness.
	return proof, croppedImage, nil
}
