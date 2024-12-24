package examples

import (
	"fmt"
	"src/circuits"
	"src/secureCamera"
)

func TakeAndVerifyPictures(flag string, t string) {
	// Create a new camera
	cam, err := secureCamera.NewCamera()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	// fmt.Println(cam)

	// Take an image & generate a proof
	err = cam.TakePicture(flag, t)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	// fmt.Print(cam.Pictures[0])

	// Verify the proof
	circuits.Verifier(cam.Proofs[0])
}
