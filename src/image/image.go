package image

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
)

const (
	// The size of an image in pixels.
	N = 14 // Remember an image will have N*N pixels
)

type Pixel struct {
	R uint8
	G uint8
	B uint8
}

type Image struct {
	Pixels   [N * N]Pixel
	Metadata map[string]interface{}
}

// Can create a "white" or "black" or "random" image
func NewImage(flag string) (Image, error) {
	newImage := Image{
		Pixels:   [N * N]Pixel{},
		Metadata: make(map[string]interface{}),
	}

	// Create a black and white pixel
	blackPixel := Pixel{R: 0, G: 0, B: 0}
	whitePixel := Pixel{R: 255, G: 255, B: 255}

	// For each pixel
	for row := 0; row < N; row++ {
		for col := 0; col < N; col++ {
			if flag == "" {
				return newImage, nil
			}

			if flag == "black" {

				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				// Set pixels as black
				newImage.Pixels[idx] = blackPixel
			}

			if flag == "white" {
				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				// Set pixels as black
				newImage.Pixels[idx] = whitePixel
			}

			if flag == "random" {
				// Generate a random number between 0 and 255
				n, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return Image{}, err
				}

				// Convert the result to uint8
				randomUint8 := uint8(n.Int64())

				// Create a random pixel
				randomPixel := Pixel{R: randomUint8, G: randomUint8, B: randomUint8}

				// Translate the 2D location (x,y) into a 1D index.
				idx := row*N + col

				// Set pixels as randomPixel
				newImage.Pixels[idx] = randomPixel
			}
		}
	}

	// Set metadata
	newImage.Metadata["author"] = "John Doe"
	newImage.Metadata["N"] = N
	newImage.Metadata["height"] = N
	newImage.Metadata["width"] = N

	return newImage, nil
}

// Pack the input pixel's R, G, B uint8 values into a single uint32
// This can be used to be more efficient in
func (pixel Pixel) PackRGB() uint32 {
	return uint32(pixel.R)<<16 | uint32(pixel.G)<<8 | uint32(pixel.B)
}

// PrintImage outputs the image in a 16x16 grid format.
func (img *Image) PrintImage() {
	// For each row
	for row := 0; row < N; row++ {
		// Print all indices in the row
		for col := 0; col < N; col++ {
			currentIdx := row*N + col
			pixel := img.Pixels[currentIdx]
			// Print pixel in (R, G, B) format
			fmt.Printf("(%3d, %3d, %3d) ", pixel.R, pixel.G, pixel.B)
		}
		fmt.Println() // New line after each row
	}
}

// Return the JSON encoded version of an image as bytes.
func (img Image) ToByte() []byte {
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
func (img Image) ToBigEndian() []byte {

	// Define the picture as a "z value of a field element (fr.element)" that's converted into a big endian
	img_bytes := img.ToByte() // Encode image into bytes using JSON

	var msgFr fr.Element // Define a field element

	// (https://pkg.go.dev/github.com/consensys/gnark-crypto@v0.9.1/ecc/bn254/fr#Element.SetBytes)
	msgFr.SetBytes(img_bytes)                 // Set the image bytes as the z value for the fr.Element
	big_endian_bytes_Image := msgFr.Marshal() // Convert z value to a big endian slice

	return big_endian_bytes_Image
}

// Return an FrImage that has FrPixels equivalent to RGBPixels in the img.
func (img Image) ToFrImage() FrImage {
	// Create a new FrImage
	frImage := FrImage{}

	// For each row of length N
	for row := 0; row < N; row++ {
		// For each col index in the row
		for col := 0; col < N; col++ {

			currentIdx := row*N + col

			// Get RGBPixel
			pixel := img.Pixels[currentIdx]

			// Set RGBPixel as an FrPixel in the newly created FrImage
			frImage.SetPixel(col, row, pixel)
		}
	}

	return frImage
}

func (img Image) Sign(secretKey signature.Signer) []byte {

	// 3. Instantiate MIMC BN254 hash function, to be used in signing the image
	hFunc := hash.MIMC_BN254.New()

	img_big_endian := img.ToBigEndian()

	// 4. Sign the image (must first turn the image into a Big Endian)
	signature, err := secretKey.Sign(img_big_endian, hFunc)
	if err != nil {
		fmt.Println("Error while signing image: " + err.Error())
	}

	return signature
}
