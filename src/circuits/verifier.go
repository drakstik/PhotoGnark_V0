package circuits

import (
	"github.com/consensys/gnark/backend/groth16"
)

func Verifier(proof Proof) (bool, error) {
	// Verify the PCD Proof.
	err := groth16.Verify(proof.PCD_Proof, proof.VK.VeriKey, proof.Public_Witness)
	if err != nil {
		return false, err
	}

	return true, err
}
