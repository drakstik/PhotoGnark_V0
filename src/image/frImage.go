package image

import "github.com/consensys/gnark/frontend"

type FrImage struct {
	Pixels [N * N]frontend.Variable // Secret
}

/* Start of Interface functions. */

// This SetPixel function packs the pixel before setting it at the location (x=col, y=row) in the img,
// where (0,0) is top left corner.
func (img *FrImage) SetPixel(col int, row int, pixel RGBPixel) {
	// Flatten the 2D location into a 1D index.
	idx := row*N + col

	// Set the packed pixel at the 1D index.
	img.Pixels[idx] = frontend.Variable(pixel.PackRGB())
}

/* End of Interface functions. */
