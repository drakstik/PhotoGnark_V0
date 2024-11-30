package secureCamera

import (
	"fmt"
	"src/circuits"
	"src/image"

	"github.com/consensys/gnark-crypto/ecc"
)

type SecureCamera struct {
	IdKeys   circuits.Keys
	CropKeys circuits.Keys
	Pictures []image.Image
	Proofs   []circuits.Proof
}

func NewCamera() (SecureCamera, error) {
	fmt.Println("[Camera] Generating new camera")
	// 1. Generate keys
	idKeys, cropKey, err := circuits.Generator(image.N, ecc.BN254.ScalarField()) // Generate a secret key for signing
	if err != nil {
		return SecureCamera{}, err
	}

	return SecureCamera{IdKeys: idKeys, CropKeys: cropKey}, nil

}
