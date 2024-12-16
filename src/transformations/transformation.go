package transformations

import (
	"math/big"
	"src/circuits"
	"src/image"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
)

type Transformation interface {
	TransformAndProve(proving_key groth16.ProvingKey, secretKey signature.Signer, img image.Image, proof_in circuits.Proof, security_parameter *big.Int) (circuits.Proof, error)
	Transform(image.Image) (image.Image, error)
	GetType() string
}
