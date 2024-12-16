package examples

import (
	"fmt"
	"src/circuits"
	"src/editor"
	"src/image"
	"src/secureCamera"
	"src/transformations"

	"github.com/consensys/gnark-crypto/ecc"
)

func CropAndProve() {
	// Create a new camera
	cam, err := secureCamera.NewCamera()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	// fmt.Println(cam)

	// Take an image & generate a proof
	err = cam.TakePicture("white", "crop")
	if err != nil {
		fmt.Println("Error: ", err)
	}

	// Verify the proof
	circuits.Verifier(cam.Proofs[0])

	// Create a new editor
	editor, err := editor.NewEditor()
	if err != nil {
		fmt.Println("Error: ", err)
	}

	// Create a new Crop Transformation
	t := transformations.CropT{
		N:  image.N,
		X0: 5,
		Y0: 5,
		X1: 5,
		Y1: 5,
	}

	t.TransformAndProve(editor.CropKeys.ProvKey, editor.IdKeys.SecKey, cam.Pictures[0], cam.Proofs[0], ecc.BN254.ScalarField())
}
