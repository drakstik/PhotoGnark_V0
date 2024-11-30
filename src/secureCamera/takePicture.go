package secureCamera

import (
	"fmt"
	"src/circuits"
	"src/editor"
	"src/image"
	"src/transformations"

	"github.com/consensys/gnark-crypto/ecc"
)

func (cam *SecureCamera) TakePicture(flag string, t string) error {
	// Take a picture
	img := image.NewImage(flag)

	// Use the camera's key to sign the original picture
	signature := img.Sign(cam.IdKeys.SecKey)

	// Construct a proof with only the image and signature
	proof := circuits.Proof{Signature: signature}

	// Create permissible transformation(s)
	if t == "crop" {
		tr := transformations.CropT{}
		// Create a pcd_proof
		fmt.Println("[Camera] Starting Crop Prover")
		proof, err := editor.Prover(cam.CropKeys.ProvKey, cam.IdKeys.SecKey, img, &tr, proof, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}

		// Add the verifying and public keys.
		proof.VK.VeriKey = cam.CropKeys.VeriKey.VeriKey
		proof.VK.PublicKey = cam.IdKeys.VeriKey.PublicKey
		// Save the image and proof on the camera.
		cam.Pictures = append(cam.Pictures, img)
		cam.Proofs = append(cam.Proofs, proof)
	} else if t == "identity" {
		tr := transformations.IdentityT{}
		fmt.Println("[Camera] Starting Identity Prover")

		// Create a pcd_proof
		proof, err := editor.Prover(cam.IdKeys.ProvKey, cam.IdKeys.SecKey, img, &tr, proof, ecc.BN254.ScalarField())
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
