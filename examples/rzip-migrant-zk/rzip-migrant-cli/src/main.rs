use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use rzip_migrant_core::{MigrationClaim, PermitType, RegionCode, Status};
use rzip_migrant_crypto::StatusProver;

#[derive(Debug, Clone, ValueEnum)]
enum Region {
    Moscow,
    SaintPetersburg,
    MoscowOblast,
}

impl From<Region> for RegionCode {
    fn from(r: Region) -> Self {
        match r {
            Region::Moscow => RegionCode::Moscow,
            Region::SaintPetersburg => RegionCode::SaintPetersburg,
            Region::MoscowOblast => RegionCode::MoscowOblast,
        }
    }
}

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a mock migration claim (for testing)
    MockClaim {
        #[arg(long, default_value = "did:mzk:test")]
        subject_did: String,
    },
    /// Prove legal status in a region
    Prove {
        #[arg(long)]
        region: Region,
    },
    /// Verify a proof
    Verify {
        #[arg(long)]
        file: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        #[allow(unused_variables)]
        Commands::MockClaim { subject_did } => {
            let now = Utc::now();
            let claim = MigrationClaim {
                subject_commitment: [1u8; 32], // mock
                status: Status::Valid,
                valid_until: now + chrono::Duration::days(180),
                region: RegionCode::Moscow,
                permit_type: PermitType::Patent,
                restrictions: vec![],
                issuance_date: now - chrono::Duration::days(10),
                signature: vec![2u8; 64], // mock
            };

            let json = serde_json::to_string_pretty(&claim)?;
            println!("{}", json);
            Ok(())
        }

        Commands::Prove { region } => {
            let now = Utc::now().timestamp();
            let claim = MigrationClaim {
                subject_commitment: [1u8; 32],
                status: Status::Valid,
                valid_until: Utc::now() + chrono::Duration::days(180),
                region: RegionCode::Moscow,
                permit_type: PermitType::Patent,
                restrictions: vec![],
                issuance_date: Utc::now(),
                signature: vec![],
            };

            let prover = StatusProver::new();
            let target_region = RegionCode::from(region.clone());
            let proof = prover.prove_valid_in_region(&claim, target_region, now)?;

            let file = format!("proof_{:?}_valid.json", region);
            let json = serde_json::to_string_pretty(&proof)?;
            std::fs::write(&file, &json)?;

            println!("✅ Proof created: {}", file);
            println!("📍 Proves: valid status in {:?}", region);
            println!("📆 Valid until: {}", proof.claimed_valid_until);
            println!("📊 Size: {} bytes", json.len());
            Ok(())
        }

        Commands::Verify { file } => {
            let data = std::fs::read_to_string(file)
                .with_context(|| format!("failed to read {}", file))?;
            let proof: rzip_migrant_crypto::StatusProof = serde_json::from_str(&data)?;

            println!("🔍 Verifying {}...", file);
            println!("📊 Proof size: {} bytes", data.len());
            println!("📍 Claimed region: {:?}", proof.claimed_region);
            println!("📝 Claimed permit: {:?}", proof.claimed_permit);
            println!("📅 Valid until: {}", proof.claimed_valid_until);
            println!("⏰ Generated at: {}", proof.proof_generation_time);

            let prover = StatusProver::new();
            let valid = prover.verify(&proof)?;

            if valid {
                println!("✅ Proof is VALID");
                println!("🕒 Current time: {}", Utc::now().timestamp());
            } else {
                println!("❌ Proof is INVALID");
                println!("🕒 Current time: {}", Utc::now().timestamp());
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
