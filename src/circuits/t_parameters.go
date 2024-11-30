package circuits

import "github.com/consensys/gnark/frontend"

type FrCropT struct {
	N  frontend.Variable
	X0 frontend.Variable
	Y0 frontend.Variable
	X1 frontend.Variable
	Y1 frontend.Variable
}
