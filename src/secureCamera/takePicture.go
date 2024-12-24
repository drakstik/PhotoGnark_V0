package secureCamera

import (
	"fmt"
	"src/circuits"
	"src/image"
	"src/transformations"

	"github.com/consensys/gnark-crypto/ecc"
)

func (cam *SecureCamera) TakePicture(flag string, legalTransformation string) error {
	fmt.Println("[Camera] Taking a picture")
	// Take a picture
	img, err := image.NewImage(flag)
	if err != nil {
		fmt.Println("Error while creating new image: " + err.Error())
	}

	// Use the camera's key to sign the original picture
	signature := img.Sign(cam.IdKeys.SecKey)

	// Construct a proof with only the image and signature
	proof := circuits.Proof{Signature: signature}

	// Create permissible transformation(s)
	if legalTransformation == "crop" {
		// This cropT will not crop any of the pixels.
		tr := transformations.CropT{
			N:  image.N,
			X0: 0,
			Y0: 0,
			X1: image.N - 1,
			Y1: image.N - 1,
		}

		// Create a pcd_proof using an identity crop transformation
		fmt.Println("[Camera] Starting Crop Prover")
		proof, img, err := tr.TransformAndProve(cam.CropKeys.ProvKey, cam.IdKeys.SecKey, img, proof, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}

		// Add the verifying and public keys.
		proof.VK.VeriKey = cam.CropKeys.VeriKey.VeriKey
		proof.VK.PublicKey = cam.IdKeys.VeriKey.PublicKey

		// Save the image and proof on the camera.
		cam.Pictures = append(cam.Pictures, img)
		cam.Proofs = append(cam.Proofs, proof)

	} else if legalTransformation == "identity" {
		tr := transformations.IdentityT{}
		fmt.Println("[Camera] Starting Identity Prover")

		// Create a pcd_proof
		proof, img, err := tr.TransformAndProve(cam.IdKeys.ProvKey, cam.IdKeys.SecKey, img, proof, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}

		// Add the verifying and public keys.
		proof.VK.VeriKey = cam.IdKeys.VeriKey.VeriKey
		proof.VK.PublicKey = cam.IdKeys.VeriKey.PublicKey

		// Save the image and proof on the camera.
		cam.Pictures = append(cam.Pictures, img)
		cam.Proofs = append(cam.Proofs, proof)
	}

	// TODO: camera should save proofs & author on decentralized ledger as well (IPFS??)
	return nil

}
