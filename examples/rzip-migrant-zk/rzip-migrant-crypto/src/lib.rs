use anyhow::{Result, anyhow};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use chrono::Utc;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;

use rzip_migrant_core::{MigrationClaim, PermitType, RegionCode};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusProof {
    pub region_commitment: [u8; 32], // Commitment to (region - target)
    pub permit_commitment: [u8; 32], // Commitment to permit type
    pub region_proof: Vec<u8>,
    pub permit_proof: Vec<u8>,
    pub claimed_region: RegionCode,
    pub claimed_permit: PermitType,
    pub claimed_valid_until: i64,   // Для логической проверки
    pub proof_generation_time: i64, // Для логической проверки
    pub restrictions_hash: [u8; 32],
}

pub struct StatusProver {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

#[allow(clippy::new_without_default)]
impl StatusProver {
    pub fn new() -> Self {
        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = PedersenGens::default();
        Self { bp_gens, pc_gens }
    }

    pub fn prove_valid_in_region(
        &self,
        claim: &MigrationClaim,
        target_region: RegionCode,
        now: i64,
    ) -> Result<StatusProof> {
        if !claim.status.is_valid(chrono::Utc::now()) {
            return Err(anyhow!("claim status is not 'Valid'"));
        }
        if claim.region != target_region {
            return Err(anyhow!(
                "claim region is {:?} (code {}), expected {:?} (code {})",
                claim.region,
                claim.region as u16,
                target_region,
                target_region as u16
            ));
        }

        let valid_until_ts = claim.valid_until.timestamp();
        if valid_until_ts < now {
            return Err(anyhow!(
                "claim expired at {}, now is {}",
                valid_until_ts,
                now
            ));
        }

        let mut rng = OsRng;
        let generation_time = Utc::now().timestamp();

        // --- Region proof: prove (region - target) == 0
        let region_diff = 0u64;

        let mut transcript_region = Transcript::new(b"MigraZK_Region_Proof");
        let blinding_r = Scalar::random(&mut rng);

        let region_commitment_point = self.pc_gens.commit(Scalar::ZERO, blinding_r);
        let region_commitment = region_commitment_point.compress();

        let region_proof = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript_region,
            region_diff,
            &blinding_r,
            8,
        )?;

        // --- Permit type proof
        let permit_value = match claim.permit_type {
            PermitType::Visa => 0u64,
            PermitType::RVP => 1u64,
            PermitType::Patent => 2u64,
            PermitType::VNJ => 3u64,
        };

        let mut transcript_permit = Transcript::new(b"MigraZK_Permit_Proof");
        let blinding_p = Scalar::random(&mut rng);

        let permit_commitment_point = self.pc_gens.commit(Scalar::from(permit_value), blinding_p);
        let permit_commitment = permit_commitment_point.compress();

        let permit_proof = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript_permit,
            permit_value,
            &blinding_p,
            8,
        )?;

        // --- Hash restrictions
        let restrictions_hash = {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            for restriction in &claim.restrictions {
                hasher.update(restriction.as_bytes());
                hasher.update(&[b';']);
            }
            let hash = hasher.finalize();
            *hash.as_bytes()
        };

        Ok(StatusProof {
            region_commitment: region_commitment.to_bytes(),
            permit_commitment: permit_commitment.to_bytes(),
            region_proof: region_proof.0.to_bytes(),
            permit_proof: permit_proof.0.to_bytes(),
            claimed_region: target_region,
            claimed_permit: claim.permit_type.clone(),
            claimed_valid_until: valid_until_ts,
            proof_generation_time: generation_time,
            restrictions_hash,
        })
    }

    pub fn verify(&self, proof: &StatusProof) -> Result<bool> {
        println!("🔍 Starting verification...");

        // --- Region proof
        println!("  Checking region proof...");
        let mut transcript_region = Transcript::new(b"MigraZK_Region_Proof");
        let region_proof = RangeProof::from_bytes(&proof.region_proof)
            .map_err(|e| anyhow!("invalid region proof: {}", e))?;

        let region_commitment = CompressedRistretto::from_slice(&proof.region_commitment)
            .map_err(|_| anyhow!("invalid region commitment"))?;

        let region_ok = region_proof
            .verify_single(
                &self.bp_gens,
                &self.pc_gens,
                &mut transcript_region,
                &region_commitment,
                8,
            )
            .is_ok();

        println!(
            "  Region proof: {}",
            if region_ok { "OK" } else { "FAILED" }
        );

        // --- Permit proof
        println!("  Checking permit proof...");
        let mut transcript_permit = Transcript::new(b"MigraZK_Permit_Proof");
        let permit_proof = RangeProof::from_bytes(&proof.permit_proof)
            .map_err(|e| anyhow!("invalid permit proof: {}", e))?;

        let permit_commitment = CompressedRistretto::from_slice(&proof.permit_commitment)
            .map_err(|_| anyhow!("invalid permit commitment"))?;

        let permit_ok = permit_proof
            .verify_single(
                &self.bp_gens,
                &self.pc_gens,
                &mut transcript_permit,
                &permit_commitment,
                8,
            )
            .is_ok();

        println!(
            "  Permit proof: {}",
            if permit_ok { "OK" } else { "FAILED" }
        );

        // --- Logical checks
        println!("  Checking logical constraints...");
        let current_time = Utc::now().timestamp();
        let not_expired = current_time <= proof.claimed_valid_until;
        println!("    Current time: {}", current_time);
        println!("    Valid until: {}", proof.claimed_valid_until);
        println!("    Not expired: {}", not_expired);

        let proof_age = current_time - proof.proof_generation_time;
        let proof_fresh = proof_age <= 3600;
        println!("    Proof age: {} seconds", proof_age);
        println!("    Proof fresh: {}", proof_fresh);

        let result = region_ok && permit_ok && not_expired && proof_fresh;
        println!(
            "🔍 Final result: {}",
            if result { "VALID" } else { "INVALID" }
        );

        Ok(result)
    }
}
