package Example

import (
	"fmt"
	"src/image"
)

func CropExample() {
	img := image.NewImage("white")

	z, _, err := img.Crop(5, 5, 7, 5)
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
	}

	z.Image.PrintImage()
}
