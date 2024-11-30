package editor

import (
	"math/big"
	"src/circuits"
	"src/image"
	"src/transformations"

	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
)

func Prover(proving_key groth16.ProvingKey, secretKey signature.Signer, img image.Image, t transformations.Transformation, proof_in circuits.Proof, security_parameter *big.Int) (circuits.Proof, error) {

	// TODO: Also verify signature if PCD_Proof == nil.
	if proof_in.PCD_Proof == nil {

		// Return the proof, image, signature and public witness.
		return t.Prove(proving_key, secretKey, img, proof_in, security_parameter)

		// // Create a new CropCircuit struct using the image_in and a secret key
		// circuit, err := t.NewCircuit(img, secretKey)
		// if err != nil {
		// 	return circuits.Proof{}, err
		// }

		// // Create the secret witness from the circuit
		// secret_witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
		// if err != nil {
		// 	return circuits.Proof{}, err
		// }

		// // Set the security parameter and compile a constraint system (aka compliance_predicate)
		// compliance_predicate, err := frontend.Compile(security_parameter, r1cs.NewBuilder, &CropCircuit{})
		// if err != nil {
		// 	return circuits.Proof{}, err
		// }

		// // Prove the secret witness adheres to the compliance predicate, using the given proving key
		// pcd_proof, err := groth16.Prove(compliance_predicate, proving_key, secret_witness)
		// if err != nil {
		// 	return circuits.Proof{}, err
		// }

		// // Create a public witness
		// publicWitness, err := secret_witness.Public()
		// if err != nil {
		// 	return circuits.Proof{}, err
		// }

		// // Return the proof, image, signature and public witness.
		// return circuits.Proof{PCD_Proof: pcd_proof, Signature: proof_in.Signature, Public_Witness: publicWitness}, nil
	} else {

	}

	return circuits.Proof{}, nil
}
