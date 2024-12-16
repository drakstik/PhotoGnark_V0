package circuits

import (
	"fmt"
	"src/image"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type Fr_SquareArea struct {
	topLeft     Fr_Location
	bottomRight Fr_Location
}

type Fr_Location struct {
	X frontend.Variable
	Y frontend.Variable
}

type CropCircuit struct {
	PublicKey         eddsa.PublicKey   `gnark:",public"`
	EdDSA_Signature   eddsa.Signature   `gnark:",public"`
	ImageBytes        frontend.Variable // FrImage as a Big Endian
	FrImage           image.FrImage
	Transformed_Image image.FrImage `gnark:", public"`
	Params            FrCropT
}

func (circuit *CropCircuit) Define(api frontend.API) error {
	// Verify the image has been signed
	circuit.VerifySignature(api)

	// Check that params are within image bounds.
	circuit.CheckParams(api)

	// Check that the transformation & parameters are legal
	// & tranform the image pixels
	croppedImage := circuit.Transform(api)

	fmt.Println("Out of CheckTransform")
	img := logderivlookup.New(api)
	for row := range image.N {
		for col := range image.N {
			flatIdx := row*image.N + col
			img.Insert(circuit.FrImage.Pixels[flatIdx])
		}
	}

	img2 := logderivlookup.New(api)
	for row := range image.N {
		for col := range image.N {
			flatIdx := row*image.N + col
			img2.Insert(croppedImage.Pixels[flatIdx])
		}
	}

	// check if they equal the circuit's transformed_image
	for row := 0; row < image.N; row++ {
		for col := 0; col < image.N; col++ {
			currentX := frontend.Variable(col)
			currentY := frontend.Variable(row)

			// Lookup the current pixel
			currentFlatIdx := api.Add(api.Mul(currentY, circuit.Params.N), currentX)
			currentPixel := img.Lookup(currentFlatIdx)[0]
			currentPixel2 := img2.Lookup(currentFlatIdx)[0]

			api.AssertIsEqual(currentPixel, currentPixel2)

		}
	}

	fmt.Println("out")

	return nil
}

func (circuit *CropCircuit) VerifySignature(api frontend.API) error {
	// Create a new Twisted Edwards Curve
	edCurve, err := twistededwards.NewEdCurve(api, 1)
	if err != nil {
		return err
	}

	// Create the MiMC hash function for Gnark circuits
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Verify the signature against the Image bytes,
	// using the public key, twisted edwards curve and hash function
	eddsa.Verify(edCurve, circuit.EdDSA_Signature, circuit.ImageBytes, circuit.PublicKey, &mimc)

	return nil
}

func (circuit *CropCircuit) CheckParams(api frontend.API) {
	nMinusOne := api.Sub(circuit.Params.N, 1)
	// Check that params <= (N-1)
	api.AssertIsLessOrEqual(circuit.Params.X0, nMinusOne)
	api.AssertIsLessOrEqual(circuit.Params.Y0, nMinusOne)
	api.AssertIsLessOrEqual(circuit.Params.X1, nMinusOne)
	api.AssertIsLessOrEqual(circuit.Params.Y1, nMinusOne)

	zero, _ := api.Compiler().ConstantValue(0)
	// Check that params >= 0
	api.AssertIsLessOrEqual(zero, circuit.Params.X0)
	api.AssertIsLessOrEqual(zero, circuit.Params.Y0)
	api.AssertIsLessOrEqual(zero, circuit.Params.X1)
	api.AssertIsLessOrEqual(zero, circuit.Params.Y1)
}

func (circuit *CropCircuit) Transform(api frontend.API) image.FrImage {
	// Initialize zero as a variable
	zero := frontend.Variable(0)

	// Initialize FrImage for returning
	newImage := image.FrImage{}

	// Initialize the cropArea using the params as fields
	cropArea := Fr_SquareArea{
		topLeft:     Fr_Location{X: circuit.Params.X0, Y: circuit.Params.Y0},
		bottomRight: Fr_Location{X: circuit.Params.X1, Y: circuit.Params.Y1},
	}

	// Initialize the lookup table
	img := logderivlookup.New(api)
	for row := range image.N {
		for col := range image.N {
			flatIdx := row*image.N + col
			img.Insert(circuit.FrImage.Pixels[flatIdx])
		}
	}

	// newImg := logderivlookup.New(api)

	for row := 0; row < image.N; row++ {
		for col := 0; col < image.N; col++ {

			currentX := frontend.Variable(col)
			currentY := frontend.Variable(row)

			// Calculate where the cropped pixel will be if shifted top left
			// croppedX := api.Sub(currentX, cropArea.topLeft.X)
			// croppedY := api.Sub(currentY, cropArea.topLeft.Y)

			flatIdxFr := api.Add(api.Mul(currentY, circuit.Params.N), currentX)
			// newIdx := row-

			// current <= bottomRight
			api.AssertIsLessOrEqual(currentX, cropArea.bottomRight.X)
			api.AssertIsLessOrEqual(currentY, cropArea.bottomRight.Y)

			fmt.Println("started InArea function ", col, row)
			// true if current pixel location is within the cropArea
			validPixel := api.And(api.Or(
				api.IsZero(api.Cmp(currentX, cropArea.topLeft.X)),
				api.IsZero(api.Sub(api.Cmp(currentX, cropArea.topLeft.X), 1)),
			), api.Or(
				api.IsZero(api.Cmp(currentY, cropArea.topLeft.Y)),
				api.IsZero(api.Sub(api.Cmp(currentY, cropArea.topLeft.Y), 1)),
			))

			fmt.Println("exited InArea function ", col, row)
			// Lookup the current pixel

			currentPixel := img.Lookup(flatIdxFr)[0]

			// Select the current pixel, if it's matches parameter constraints,
			// otherwise selet a black pixel
			newPixel := api.Select(validPixel, currentPixel, zero)

			flatIdx := row*image.N + col
			newImage.Pixels[flatIdx] = newPixel
			// api.Println(validParams)
		}
	}

	return newImage
}
