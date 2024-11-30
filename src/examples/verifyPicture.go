package examples

import (
	"fmt"
	"src/circuits"
	"src/secureCamera"
)

func TakeAndVerifyPictures(t string) {
	// Create a new camera
	cam, err := secureCamera.NewCamera()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	// fmt.Println(cam)

	// Take an image & generate a proof
	err = cam.TakePicture("white", t)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	// fmt.Print(cam.Pictures[0])

	// Verify the proof
	circuits.Verifier(cam.Proofs[0])
}
