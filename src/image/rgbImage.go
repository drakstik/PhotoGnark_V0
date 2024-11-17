package image

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
)

type RGBPixel struct {
	R uint8
	G uint8
	B uint8
}

type RGBImage struct {
	Pixels   [N * N]RGBPixel
	Metadata map[string]interface{}
}

type Z struct {
	Image     RGBImage
	PublicKey signature.PublicKey
}

func NewImage(flag string) RGBImage {
	newImage := RGBImage{
		Pixels:   [N * N]RGBPixel{},
		Metadata: make(map[string]interface{}),
	}

	// Create a black and white pixel
	blackPixel := RGBPixel{R: 0, G: 0, B: 0}
	whitePixel := RGBPixel{R: 255, G: 255, B: 255}

	// For each pixel
	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			if flag == "black" {

				// Set pixels as black
				newImage.SetPixel(col, row, blackPixel)
			}

			if flag == "white" {
				// Set pixels as white
				newImage.SetPixel(col, row, whitePixel)
			}
		}
	}

	// Set metadata
	newImage.Metadata["author"] = "John Doe"
	newImage.Metadata["N"] = N
	newImage.Metadata["height"] = N
	newImage.Metadata["width"] = N

	return newImage
}

// Pack the input pixel's R, G, B uint8 values into a single uint32
// This can be used to be more efficient in
func (pixel RGBPixel) PackRGB() uint32 {
	return uint32(pixel.R)<<16 | uint32(pixel.G)<<8 | uint32(pixel.B)
}

/* Start of Interface functions. */

// Get the pixel at location (x,y),
// where (x,y) is a pixel location in the 2D representation [N*N] array of pixels.
func (img RGBImage) GetPixel(col, row int) RGBPixel {
	// Translate the 2D location (x,y) into a 1D index.
	idx := row*N + col

	return img.Pixels[idx]
}

// Set the pixel at location (x,y),
// where (x,y) is a pixel location in the 2D representation [N*N] array of pixels.
func (img *RGBImage) SetPixel(col int, row int, pixel RGBPixel) {
	// Translate the 2D location (x,y) into a 1D index.
	idx := row*N + col

	img.Pixels[idx] = pixel
}

// PrintImage outputs the image in a 16x16 grid format.
func (img *RGBImage) PrintImage() {
	// For each row
	for row := 0; row < N; row++ {
		// Print all indices in the row
		for col := 0; col < N; col++ {
			pixel := img.GetPixel(col, row)
			// Print pixel in (R, G, B) format
			fmt.Printf("(%3d, %3d, %3d) ", pixel.R, pixel.G, pixel.B)
		}
		fmt.Println() // New line after each row
	}
}

/* End of Interface functions. */

// Return the JSON encoded version of an image as bytes.
func (img RGBImage) ToByte() []byte {
	encoded_image, err := json.Marshal(img)
	if err != nil {
		fmt.Println("Error while encoding image: " + err.Error())
		return []byte{}
	}

	return encoded_image
}

// Interprets image bytes as the bytes of a big-endian unsigned integer, sets z to that value, and return z value as a big endian slice.
// If this step is skipped, you get this error:
// "runtime error: slice bounds out of range".
// This step is required to define an image into something that Gnark circuits understand.
func (img RGBImage) ToBigEndian() []byte {

	// Define the picture as a "z value of a field element (fr.element)" that's converted into a big endian
	img_bytes := img.ToByte() // Encode image into bytes using JSON

	var msgFr fr.Element // Define a field element

	// (https://pkg.go.dev/github.com/consensys/gnark-crypto@v0.9.1/ecc/bn254/fr#Element.SetBytes)
	msgFr.SetBytes(img_bytes)                 // Set the image bytes as the z value for the fr.Element
	big_endian_bytes_Image := msgFr.Marshal() // Convert z value to a big endian slice

	return big_endian_bytes_Image
}

// Return an FrImage that has FrPixels equivalent to RGBPixels in the img.
func (img RGBImage) ToFrImage() FrImage {
	// Create a new FrImage
	frImage := FrImage{}

	// For each row of length N
	for row := 0; row < N; row++ {
		// For each col index in the row
		for col := 0; col < N; col++ {

			// Get RGBPixel
			pixel := img.GetPixel(col, row)

			// Set RGBPixel as an FrPixel in the newly created FrImage
			frImage.SetPixel(col, row, pixel)
		}
	}

	return frImage
}

func (img RGBImage) Sign() ([]byte, signature.PublicKey, signature.Signer) {
	// 1. Generate a secret key using ceddsa.
	secretKey, err := ceddsa.New(1, rand.Reader) // Generate a secret key for signing
	if err != nil {
		fmt.Println(err.Error())
	}

	// 2. Generate a public key
	publicKey := secretKey.Public()

	// 3. Instantiate MIMC BN254 hash function, to be used in signing the image
	hFunc := hash.MIMC_BN254.New()

	// 4. Sign the image (must first turn the image into a Big Endian)
	signature, err := secretKey.Sign(img.ToBigEndian(), hFunc)
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
	}

	return signature, publicKey, secretKey
}

// Crop the image, sign it, and return the cropped image, its public key and signature.
func (img_in RGBImage) Crop(x0, y0, x1, y1 int) (Z, []byte, error) {

	// Check that image has metadata
	if img_in.Metadata == nil {
		return Z{}, []byte{}, fmt.Errorf("Error! Image's metadata is nil.")
	}

	// Retrieve image's actual width & height from the metadata
	width, widthOk := img_in.Metadata["width"].(int)
	height, heightOk := img_in.Metadata["height"].(int)

	// Check that width and height values are valid from the Metadata map
	if !widthOk || !heightOk {
		return Z{}, []byte{}, fmt.Errorf("Error! Invalid image metadata for width and height")
	}

	// Check that the crop boundaries are within th image dimensions
	if x0 < 0 || y0 < 0 || x1 >= width || y1 >= height || x0 > x1 || y0 > y1 {
		fmt.Println(x0, y0, x1, y1)
		return Z{}, []byte{}, fmt.Errorf("Error! invalid crop dimenesions: out of bounds")
	}

	// Calculate the width and height of the cropped area
	cropWidth := x1 - x0 + 1  // + 1 because indeces start at (0,0)
	cropHeight := y1 - y0 + 1 // + 1 because indeces start at (0,0)

	// Create a black pixel
	blackPixel := RGBPixel{R: 0, G: 0, B: 0}

	// Initialize the cropped image to be outputed
	img_cropped := NewImage("")

	// For each pixel
	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {

			// Initialize pixels as black
			img_cropped.SetPixel(col, row, blackPixel)

			// If the pixel is within the cropping area and within the bounded area
			if row < cropHeight && col < cropWidth && (y0+row) < N && (x0+col) < N {
				// Set the pixel towards the top-left corner
				img_cropped.SetPixel(col, row, img_in.GetPixel(col, row))
			}

		}
	}

	// Update the metadata to reflect the new width & height of the cropped area
	img_cropped.Metadata["width"] = cropWidth
	img_cropped.Metadata["height"] = cropHeight

	// Sign the cropped image
	signature, publicKey, _ := img_cropped.Sign()

	return Z{Image: img_cropped, PublicKey: publicKey}, signature, nil
}
