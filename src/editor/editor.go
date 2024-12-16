package editor

import (
	"fmt"
	"src/circuits"
	"src/image"

	"github.com/consensys/gnark-crypto/ecc"
)

type Editor struct {
	IdKeys   circuits.Keys
	CropKeys circuits.Keys
}

func NewEditor() (Editor, error) {
	fmt.Println("[Camera] Generating new camera")
	// 1. Generate keys
	idKeys, cropKey, err := circuits.Generator(image.N, ecc.BN254.ScalarField()) // Generate a secret key for signing
	if err != nil {
		return Editor{}, err
	}

	return Editor{IdKeys: idKeys, CropKeys: cropKey}, nil

}
