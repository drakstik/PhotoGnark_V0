package camera

import (
	"fmt"
	"src/circuits"
	"src/image"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

func Generator(img image.RGBImage, t int) (PK_PP, VK_PP, SK_PP, error) {

	var frCircuit frontend.Circuit
	var cropCircuit circuits.CropCircuit
	var pk signature.PublicKey
	var sk signature.Signer

	// Translate the img into the correct circuit
	if t == circuits.CropT {
		cropCircuit, sk, pk = circuits.NewCropCircuit(img, 0, 0, 0, 0)
		frCircuit = &cropCircuit
	}

	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, frCircuit)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey, VK, err := groth16.Setup(compliance_predicate)
	if err != nil {
		fmt.Println(err.Error())
	}

	vk_PCD := VK_PP{VerifyingKey: VK, PublicKey: pk}
	pk_PCD := PK_PP{ProvingKey: provingKey, PublicKey: pk}

	return pk_PCD, vk_PCD, SK_PP{SecretKey: sk}, err
}
