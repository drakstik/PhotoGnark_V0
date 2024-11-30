package transformations

import (
	"math/big"
	"src/circuits"
	"src/image"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type IdentityT struct {
}

type FrIdentityT struct {
}

func (t IdentityT) Transform(img image.Image) (image.Image, error) {

	return img, nil
}

func (t IdentityT) GetType() string {
	return "identity"
}

func (t IdentityT) NewCircuit(img image.Image, secretKey signature.Signer) (circuits.IdentityCircuit, error) {
	digSig := img.Sign(secretKey) // Sign the image, get the Public and Secret Key

	// Assign the PK & SK to their eddsa equivilant
	var eddsa_digSig eddsa.Signature
	var eddsa_PK eddsa.PublicKey

	pk := secretKey.Public()

	eddsa_digSig.Assign(1, digSig)
	eddsa_PK.Assign(1, pk.Bytes())

	// Instantiate a new CropCircuit
	circuit := circuits.IdentityCircuit{
		PublicKey:       eddsa_PK,
		EdDSA_Signature: eddsa_digSig,
		ImageBytes:      img.ToBigEndian(),
		FrImage_A:       img.ToFrImage(),
		FrImage_B:       img.ToFrImage(),
	}

	return circuit, nil
}

func (t IdentityT) Prove(proving_key groth16.ProvingKey, secretKey signature.Signer, img image.Image, proof_in circuits.Proof, security_parameter *big.Int) (circuits.Proof, error) {
	// Create a new IdentityCircuit struct using the image_in and a secret key
	circuit, err := t.NewCircuit(img, secretKey)
	if err != nil {
		return circuits.Proof{}, err
	}

	// Create the secret witness from the circuit
	secret_witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		return circuits.Proof{}, err
	}

	// Set the security parameter and compile a constraint system (aka compliance_predicate)
	compliance_predicate, err := frontend.Compile(security_parameter, r1cs.NewBuilder, &circuits.IdentityCircuit{})
	if err != nil {
		return circuits.Proof{}, err
	}

	// Prove the secret witness adheres to the compliance predicate, using the given proving key
	pcd_proof, err := groth16.Prove(compliance_predicate, proving_key, secret_witness)
	if err != nil {
		return circuits.Proof{}, err
	}

	// Create a public witness
	publicWitness, err := secret_witness.Public()
	if err != nil {
		return circuits.Proof{}, err
	}

	proof := circuits.Proof{PCD_Proof: pcd_proof, Signature: proof_in.Signature, Public_Witness: publicWitness}
	// Return the proof, image, signature and public witness.
	return proof, nil
}
