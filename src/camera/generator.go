package camera

import (
	"src/image"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
)

type VK_PP struct {
	VerifyingKey groth16.VerifyingKey
	PublicKey    signature.PublicKey
}

type PK_PP struct {
	ProvingKey groth16.ProvingKey
	PublicKey  signature.PublicKey
}

type SK_PP struct {
	SecretKey signature.Signer
}

func Generator(img image.RGBImage) (PK_PP, VK_PP, SK_PP, error) {
	digSig, PK, SK := img.Sign()

}
