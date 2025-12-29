use anyhow::{Result, anyhow};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeProof {
    pub commitment: [u8; 32],
    pub range_proof: Vec<u8>,
    pub min_age: u8,
    pub max_age: u8,
}

pub struct AgeProver {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

#[allow(clippy::new_without_default)]
impl AgeProver {
    pub fn new() -> Self {
        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = PedersenGens::default();
        AgeProver { bp_gens, pc_gens }
    }

    pub fn prove_age(&self, secret_age: u8, min_age: u8, max_age: u8) -> Result<AgeProof> {
        if secret_age < min_age || secret_age > max_age {
            return Err(anyhow!(
                "age {} not in [{}, {}]",
                secret_age,
                min_age,
                max_age
            ));
        }

        let mut rng = OsRng;
        let mut transcript = Transcript::new(b"RZIP_Age_Proof");

        let blinding = Scalar::random(&mut rng);
        let commitment_point = self
            .pc_gens
            .commit(Scalar::from(secret_age as u64), blinding);
        let commitment = commitment_point.compress();

        let shifted = (secret_age - min_age) as u64;

        let range_bits = 8;

        let proof = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            shifted,
            &blinding,
            range_bits,
        )?;

        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&commitment.to_bytes());

        Ok(AgeProof {
            commitment: commitment_bytes,
            range_proof: proof.0.to_bytes(),
            min_age,
            max_age,
        })
    }

    pub fn verify_age_proof(&self, proof: &AgeProof) -> Result<bool> {
        let mut transcript = Transcript::new(b"RZIP_Age_Proof");

        let commitment = CompressedRistretto::from_slice(&proof.commitment)
            .map_err(|_| anyhow!("invalid commitment bytes"))?;

        let range_proof = RangeProof::from_bytes(&proof.range_proof)
            .map_err(|e| anyhow!("invalid range proof: {}", e))?;

        let min_scalar = Scalar::from(proof.min_age as u64);

        let c_point = commitment
            .decompress()
            .ok_or_else(|| anyhow!("commitment decompression failed"))?;

        let g_times_min = self.pc_gens.B * min_scalar;
        let adjusted_point: RistrettoPoint = c_point - g_times_min;
        let adjusted_commitment = adjusted_point.compress();

        let range_bits = 8;

        match range_proof.verify_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            &adjusted_commitment,
            range_bits,
        ) {
            Ok(()) => Ok(true),
            Err(_e) => Ok(false),
        }
    }
}
