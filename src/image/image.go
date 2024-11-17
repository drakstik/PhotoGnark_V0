package image

const (
	// The size of an image in pixels.
	N = 8
)

// Image is an interface that represents an NxN image with metadata.
type Image interface {
	// Set the pixel at location (x,y), considering the image is a 2D
	// array that is [N]*[N]
	SetPixel(int, int, RGBPixel) error
	// Print the image to console. Does nothing for FrImages.
	PrintImage()
}
