use rzip_core::Credential;
use rzip_crypto::{AgeProof, AgeProver};

#[derive(Debug, Clone)]
pub enum ProofType {
    AgeProof(AgeProof),
}

#[derive(Debug, Clone)]
pub struct VerifiableCredential {
    pub credential: Credential,
    pub proof: ProofType,
}

impl VerifiableCredential {
    pub fn verify(&self) -> bool {
        let prover = AgeProver::new();
        match &self.proof {
            ProofType::AgeProof(age_proof) => {
                if self.credential.claim.value_commitment != age_proof.commitment {
                    return false;
                }
                prover.verify_age_proof(age_proof).unwrap_or(false)
            }
        }
    }
}
