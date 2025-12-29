use chrono::Utc;
use clap::{Parser, Subcommand};
use szip_core::{Claim, Credential, Did};
use szip_crypto::{AgeProof, AgeProver};
use szip_verifiable::VerifiableCredential;
use std::fs;
use std::time::Instant;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a DID
    CreateDid {
        #[arg(long)]
        method: String,
        #[arg(long)]
        id: String,
    },
    /// Generate ZK age proof
    ProveAge {
        #[arg(long)]
        age: u8,
        #[arg(long)]
        subject_did: String,
        #[arg(long, default_value = "did:rzip:issuer")]
        issuer_did: String,
    },
    /// Verify a proof file
    Verify {
        #[arg(long)]
        file: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProofOutput {
    commitment: String,
    proof: AgeProof,
    subject_did: String,
    issuer_did: String,
    verified_range: String,
    file: String,
    issued_at: chrono::DateTime<chrono::Utc>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::CreateDid { method, id } => {
            let did = Did::new(method, id)?;
            println!("✅ DID created: {}", did);
        }

        Commands::ProveAge {
            age,
            subject_did,
            issuer_did,
        } => {
            let subject = Did::parse(subject_did)?;
            let issuer = Did::parse(issuer_did)?;
            let prover = AgeProver::new();

            let gen_start = Instant::now();
            let proof = prover.prove_age(*age, 18, 127)?;
            let gen_time = gen_start.elapsed();

            let ver_start = Instant::now();
            let verified = prover.verify_age_proof(&proof)?;
            let ver_time = ver_start.elapsed();

            if !verified {
                return Err(anyhow::anyhow!("Internal error: self-verification failed"));
            }

            let commitment_hex = hex::encode(proof.commitment);
            let file_name = format!("age_proof_{}.json", age);

            let claim = Claim {
                subject: subject.clone(),
                attribute: "age".to_string(),
                value_commitment: proof.commitment,
                min_value: 18,
                max_value: 127,
                issued_at: Utc::now(),
            };

            let credential = Credential { issuer, claim };
            let _vc = VerifiableCredential {
                credential,
                proof: szip_verifiable::ProofType::AgeProof(proof.clone()),
            };

            let output = ProofOutput {
                commitment: commitment_hex.clone(),
                proof,
                subject_did: subject.to_string(),
                issuer_did: issuer_did.to_string(),
                verified_range: "≥ 18".to_string(),
                file: file_name.clone(),
                issued_at: Utc::now(),
            };

            let json = serde_json::to_string_pretty(&output)?;
            fs::write(&file_name, &json)?;

            println!("✅ Proof created: {}", file_name);
            println!("📊 Commitment: {}", &commitment_hex[..8]);
            println!("🔒 Proves: age ≥ 18");
            println!("⏱️  Proof size: {} bytes", json.len());
            println!("🕒 Generation: {:?}", gen_time);
            println!("🕒 Verification: {:?}", ver_time);
        }

        Commands::Verify { file } => {
            let data = fs::read_to_string(file)?;
            let output: ProofOutput = serde_json::from_str(&data)?;

            let subject = Did::parse(&output.subject_did)?;
            let issuer = Did::parse(&output.issuer_did)?;

            let claim = Claim {
                subject,
                attribute: "age".to_string(),
                value_commitment: output.proof.commitment,
                min_value: output.proof.min_age,
                max_value: output.proof.max_age,
                issued_at: output.issued_at,
            };

            let vc = VerifiableCredential {
                credential: Credential { issuer, claim },
                proof: szip_verifiable::ProofType::AgeProof(output.proof),
            };

            println!("🔍 Verifying proof from {}...", file);
            let ver_start = Instant::now();
            let valid = vc.verify();
            let ver_time = ver_start.elapsed();

            if valid {
                println!("✅ Proof is VALID");
                println!(
                    "🎉 Subject is ≥ {} years old",
                    vc.credential.claim.min_value
                );
                println!("👤 DID: {}", vc.credential.claim.subject);
                println!("📅 Issued: {}", vc.credential.claim.issued_at.to_rfc3339());
                println!("🕒 Verification time: {:?}", ver_time);
            } else {
                println!("❌ Proof is INVALID or corrupted");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
