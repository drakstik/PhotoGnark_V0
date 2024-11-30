package circuits

import (
	"math/big"

	"crypto/rand"

	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type Keys struct {
	ProvKey groth16.ProvingKey
	VeriKey VK
	SecKey  signature.Signer
}

func NewSecretKey() (signature.Signer, error) {
	// 1. Generate a secret key using ceddsa.
	sk, err := ceddsa.New(1, rand.Reader) // Generate a secret key for signing
	if err != nil {
		return nil, err
	}

	return sk, nil
}

// This function generates keys and constraint system for an different transformations
func Generator(max_image_size int, security_parameter *big.Int) (Keys, Keys, error) {

	sk, err := NewSecretKey()
	if err != nil {
		return Keys{}, Keys{}, err
	}

	//------------- Compiling Identity Transformation Keys ------------------------

	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate_id, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &IdentityCircuit{})
	if err != nil {
		return Keys{}, Keys{}, err
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey_id, vk_id, err := groth16.Setup(compliance_predicate_id)
	if err != nil {
		return Keys{}, Keys{}, err
	}

	//------------- Compiling Crop Transformation Keys ------------------------

	// Set the security parameter (BN254) and compile a constraint system (aka compliance_predicate)
	compliance_predicate_crop, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &CropCircuit{})
	if err != nil {
		return Keys{}, Keys{}, err
	}

	// Generate PCD Keys from the compliance_predicate
	provingKey_crop, vk_crop, err := groth16.Setup(compliance_predicate_crop)
	if err != nil {
		return Keys{}, Keys{}, err
	}

	idKeys := Keys{ProvKey: provingKey_id, VeriKey: VK{VeriKey: vk_id, PublicKey: sk.Public()}, SecKey: sk}
	cropKeys := Keys{ProvKey: provingKey_crop, VeriKey: VK{VeriKey: vk_crop, PublicKey: sk.Public()}, SecKey: sk}

	return idKeys, cropKeys, err
}
