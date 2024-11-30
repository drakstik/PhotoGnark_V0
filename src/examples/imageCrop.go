package examples

import (
	"fmt"
	"src/image"
	"src/transformations"
)

func CropExample(x0, y0, x1, y1 int) {
	img := image.NewImage("white")

	t := transformations.CropT{N: image.N, X0: x0, Y0: y0, X1: x1, Y1: y1}

	cropped, err := t.Transform(img)
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
	}

	cropped.PrintImage()
}
