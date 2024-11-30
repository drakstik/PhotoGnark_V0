package circuits

import (
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type Proof struct {
	PCD_Proof      groth16.Proof
	Signature      []byte
	Public_Witness witness.Witness
	VK             VK
}

type VK struct {
	VeriKey   groth16.VerifyingKey
	PublicKey signature.PublicKey
}
