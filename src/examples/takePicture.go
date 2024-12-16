package examples

import (
	"fmt"
	"src/secureCamera"
)

func NewCameraTakePicture(t string) {

	cam, err := secureCamera.NewCamera()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	fmt.Println(cam.IdKeys.SecKey)

	// Take an image & generate a proof
	err = cam.TakePicture("white", t)
	if err != nil {
		fmt.Println("(TakePicture) Error: ", err)
	}

	// fmt.Print(cam.Pictures[0])
	// fmt.Print(cam.Proofs[0])
}
