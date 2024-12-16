package main

import (
	ex "src/examples"
)

func main() {

	/* Start of Gnark Examples */
	// ex.LookupExample1()

	/* End of Gnark Examples */

	// ex.CropExample(0, 0, image.N-1, image.N-1)
	ex.CropExample(3, 2, 5, 3)

	// ex.NewCameraTakePicture("crop")

	// ex.TakeAndVerifyPictures("identity")
}
