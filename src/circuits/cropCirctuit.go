package circuits

import (
	"errors"
	"fmt"
	"math/big"
	"src/image"

	"github.com/consensys/gnark/constraint/solver"
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

func WithinCropArea(api frontend.API, frRow, frCol frontend.Variable, cropArea Fr_SquareArea) frontend.Variable {
	//	true if col >= X0 && row >= Y0
	//		 && col <= X1 && row <= Y1
	withinCropArea := api.And(
		api.And(
			api.Or(
				api.IsZero(api.Cmp(
					frCol,
					cropArea.topLeft.X,
				)),
				api.IsZero(api.Sub(api.Cmp(
					frCol,
					cropArea.topLeft.X,
				), 1)),
			),
			api.Or(
				api.IsZero(api.Cmp(frRow, cropArea.topLeft.Y)),
				api.IsZero(api.Sub(api.Cmp(frRow, cropArea.topLeft.Y), 1)),
			),
		),
		api.And(
			api.Or(
				api.IsZero(api.Cmp(
					frCol,
					cropArea.bottomRight.X,
				)),
				api.IsZero(api.Add(api.Cmp(frCol, cropArea.bottomRight.X), 1)),
			),
			api.Or(
				api.IsZero(api.Cmp(frRow, cropArea.bottomRight.Y)),
				api.IsZero(api.Add(api.Cmp(frRow, cropArea.bottomRight.Y), 1)),
			),
		),
	)

	// true if currentIdx is within crop area
	// withinCropArea := api.And(withinTopLeft, withinBottomRight)

	return withinCropArea
}

// type ModuloFieldCircuit[T emulated.FieldParams] struct {
// }

// func (c *ModuloFieldCircuit[T]) Define(api frontend.API) error {

// 	return nil
// }

// func (c *ModuloFieldCircuit[T]) FrModulo(api frontend.API, a, b frontend.API) error {

// 	f, err := emulated.NewField[T](api)
// 	if err != nil {
// 		return fmt.Errorf("new field: %w", err)
// 	}

// 	elA := f.NewElement(a)
// 	elB := f.NewElement(b)

// 	// Compute quotient (a / b)
// 	q := f.Div(elA, elB)

// 	// Compute remainder: a - q * b
// 	qTimesN := f.Mul(q, elB)
// 	remainder := f.Sub(elA, qTimesN)
// }

// Where a % r = b,
//
//	inputs[0] = a -- input
//	inputs[1] = r -- modulus
//	outputs[0] = b -- remainder
//	outputs[1] = (a-b)/r -- quotient
func smallModHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 2 {
		return errors.New("expected 2 outputs")
	}
	if len(inputs) != 2 {
		return errors.New("expected 2 inputs")
	}

	// Compute the quotient and remainder, NOTE: r (aka N) cannot be 0.
	outputs[1].QuoRem(inputs[0], inputs[1], outputs[0])
	//fmt.Println(inputs[0], inputs[1], outputs[0], outputs[1])
	return nil
}

func SmallMod(api frontend.API, a, r frontend.Variable) (quo, rem frontend.Variable) {
	res, err := api.Compiler().NewHint(smallModHint, 2, a, r)
	if err != nil {
		panic(err)
	}
	rem = res[0]
	quo = res[1]

	// api.Println(a, r, quo, rem)

	// To prevent against overflows, we assume that the inputs are small relative to the native feld
	nbBits := api.Compiler().Field().BitLen()/2 - 2
	bound := new(big.Int).Lsh(big.NewInt(1), uint(nbBits))

	api.AssertIsLessOrEqual(rem, bound)
	api.AssertIsLessOrEqual(quo, bound)

	api.AssertIsEqual(a, api.Add(api.Mul(quo, r), rem))
	return
}

// type ModuloCircuit struct {
// 	A, R frontend.Variable
// }

// func (c *ModuloCircuit) Define(api frontend.API) error {
// 	quo, rem := SmallMod(api, c.A, c.R)
// 	api.Println(c.A)
// 	api.Println(c.R)
// 	api.Println(quo)
// 	api.Println(rem)
// 	return nil
// }

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
	solver.RegisterHint(smallModHint)

	for row := 0; row < image.N; row++ {
		for col := 0; col < image.N; col++ {

			// Calculate the current index
			currentIdx := row*image.N + col

			// Calculate the target Index when given params and currentIdx
			// Given:
			//        leftCornerIdx := (currentRow - Y0) * N + currentCol - X0
			// As we traverse the image, we also encounter the left corner indeces and we can derive
			// a "target index" from a left corner index by assuming that
			// `leftCornerIdx == currentIdx` and we are calculating for a target index:
			//			 currentIdx = (targetRow - Y0) * N + targetCol - X0
			//			 currentIdx = N*targetRow - N*Y0 + targetCol - X0
			//			 currentIdx + N*Y0 + X0 = N*targetRow + targetCol
			//			 currentIdx + N*Y0 + X0 = targetIdx
			targetIdx := api.Add(api.Add(api.Mul(image.N, circuit.Params.Y0), circuit.Params.X0), currentIdx)

			// targetRow = targetIdx / N
			// targetCol = targetIdx % N
			// Use Div and Mul operations to compute a % r = b:
			// 		1. Compute q = a / r, where q is the quotient (using integer division).
			// 		2. Compute the remainder using remainder = a - (q * r).
			// 		3. Assert that a == (q * r) + remainder
			targetRow, targetCol := SmallMod(api, targetIdx, circuit.Params.N)

			// true if targetIdx is within crop area
			withinCropArea := WithinCropArea(api, targetRow, targetCol, cropArea)

			targetPixel := img.Lookup(targetIdx)[0]
			// api.Println(targetPixel, withinCropArea)

			// If this location is within the crop area:
			//			select pixel at targetIdx
			// Else:
			//			select black pixel
			newPixel := api.Select(withinCropArea, targetPixel, zero)

			// api.Println(newPixel)

			// Add the newPixel to the newImage
			newImage.Pixels[currentIdx] = newPixel
		}
	}

	return newImage
}
