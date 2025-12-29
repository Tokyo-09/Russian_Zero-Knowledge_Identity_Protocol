use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Table, row};
use szip_rescomply_core::CompanyProfile;
use serde_json;
use std::fs;
use std::path::PathBuf;

use szip_rescomply_core::{
    CheckResult, CounterpartyCheck, CounterpartyType, IndustryCode, Jurisdiction, RiskLevel,
    hash_identifier, hash_name,
};
use szip_rescomply_crypto::{ComplianceProof, ComplianceProver};

#[derive(Parser)]
#[command(name = "zk-rescomply")]
#[command(version = "0.1.0")]
#[command(about = "Zero-Knowledge Corporate Compliance Prover")]
#[command(long_about = "Generate and verify ZK proofs for corporate compliance with sanctions")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true)]
    verbose: bool,

    #[arg(long, global = true, default_value = "./sanctions_db")]
    sanctions_db: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new company profile
    Init {
        #[arg(long)]
        name: String,

        #[arg(long, value_enum, default_value = "ru")]
        jurisdiction: CountryArg,

        #[arg(long, default_value = "62.01")]
        industry_code: String,

        #[arg(long)]
        tax_id: Option<String>,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Generate compliance proofs
    Prove {
        #[arg(long, value_enum)]
        proof_type: ProofType,

        #[arg(long, value_enum)]
        jurisdiction: Option<CountryArg>,

        #[arg(long, default_value = "30")]
        period_days: u32,

        #[arg(long, default_values = ["ofac", "eu"])]
        sanctions_lists: Vec<String>,

        #[arg(long)]
        company_file: Option<PathBuf>,

        #[arg(long)]
        output: Option<PathBuf>,

        #[arg(long)]
        auditor: Option<String>,
    },

    /// Verify a compliance proof
    Verify {
        #[arg(long)]
        proof_file: PathBuf,

        #[arg(long)]
        company_file: Option<PathBuf>,

        #[arg(long)]
        detailed: bool,
    },

    /// Audit company against sanctions lists
    Audit {
        #[arg(long)]
        company_file: PathBuf,

        #[arg(long, default_values = ["ofac", "eu", "ru"])]
        lists: Vec<String>,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Add a counterparty to company profile
    AddCounterparty {
        #[arg(long)]
        company_file: PathBuf,

        #[arg(long)]
        identifier: String,

        #[arg(long)]
        name: Option<String>,

        #[arg(long, value_enum)]
        jurisdiction: CountryArg,

        #[arg(long, value_enum, default_value = "supplier")]
        counterparty_type: CounterpartyTypeArg,

        #[arg(long, default_values = ["ofac", "eu"])]
        check_lists: Vec<String>,

        #[arg(long)]
        result: Option<CheckResultArg>,
    },

    /// Show company compliance status
    Status {
        #[arg(long)]
        company_file: PathBuf,

        #[arg(long)]
        show_counterparties: bool,
    },

    /// Generate test data for development
    GenerateTestData {
        #[arg(long)]
        companies: Option<u32>,

        #[arg(long)]
        transactions: Option<u32>,

        #[arg(long)]
        output_dir: PathBuf,
    },
}

#[derive(Clone, ValueEnum, Debug)]
enum ProofType {
    NoOperations,     
    AllScreened,    
    WithinLimits, 
    FullCompliance,
    InternalControls,
}

#[derive(Clone, ValueEnum, Debug, Copy)]
enum CountryArg {
    Ru,
    Us,
    Gb,
    De,
    Cn,
    By,
    Crimea,
    Donetsk,
    Luhansk,
    Ir,
    Sy,
    Kp,
    Bvi,
    Cayman,
    Panama,
}

impl From<CountryArg> for Jurisdiction {
    fn from(arg: CountryArg) -> Self {
        match arg {
            CountryArg::Ru => Jurisdiction::RU,
            CountryArg::Us => Jurisdiction::US,
            CountryArg::Gb => Jurisdiction::GB,
            CountryArg::De => Jurisdiction::DE,
            CountryArg::Cn => Jurisdiction::CN,
            CountryArg::By => Jurisdiction::BY,
            CountryArg::Crimea => Jurisdiction::Crimea,
            CountryArg::Donetsk => Jurisdiction::Donetsk,
            CountryArg::Luhansk => Jurisdiction::Luhansk,
            CountryArg::Ir => Jurisdiction::IR,
            CountryArg::Sy => Jurisdiction::SY,
            CountryArg::Kp => Jurisdiction::KP,
            CountryArg::Bvi => Jurisdiction::BVI,
            CountryArg::Cayman => Jurisdiction::Cayman,
            CountryArg::Panama => Jurisdiction::Panama,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug)]
enum CounterpartyTypeArg {
    Supplier,
    Customer,
    Bank,
    Subsidiary,
    Shareholder,
    Director,
}

impl From<CounterpartyTypeArg> for CounterpartyType {
    fn from(arg: CounterpartyTypeArg) -> Self {
        match arg {
            CounterpartyTypeArg::Supplier => CounterpartyType::Supplier,
            CounterpartyTypeArg::Customer => CounterpartyType::Customer,
            CounterpartyTypeArg::Bank => CounterpartyType::Bank,
            CounterpartyTypeArg::Subsidiary => CounterpartyType::Subsidiary,
            CounterpartyTypeArg::Shareholder => CounterpartyType::Shareholder,
            CounterpartyTypeArg::Director => CounterpartyType::Director,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug)]
enum CheckResultArg {
    Clear,
    PartialMatch,
    Blocked,
}

impl From<CheckResultArg> for CheckResult {
    fn from(arg: CheckResultArg) -> Self {
        match arg {
            CheckResultArg::Clear => CheckResult::Clear,
            CheckResultArg::PartialMatch => CheckResult::PartialMatch,
            CheckResultArg::Blocked => CheckResult::Blocked,
        }
    }
}

fn print_banner() {
    println!(
        "{}",
        "┌─────────────────────────────────────┐".bright_blue()
    );
    println!(
        "{}",
        "│                                     │".bright_blue()
    );
    println!("{}", "│    🛡️  ZK-ResComply v0.1.0          │".bright_blue());
    println!(
        "{}",
        "│    Zero-Knowledge Compliance        │".bright_blue()
    );
    println!(
        "{}",
        "│                                     │".bright_blue()
    );
    println!(
        "{}",
        "└─────────────────────────────────────┘".bright_blue()
    );
    println!();
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Commands::Init {
            name,
            jurisdiction,
            industry_code,
            tax_id,
            output,
        } => {
            println!("{}", "🏢 Initializing new company profile".green().bold());
            println!("  Name: {}", name.cyan());
            println!("  Jurisdiction: {:?}", jurisdiction);
            println!("  Industry: {}", industry_code);

            let industry = IndustryCode {
                code: industry_code,
                description: "To be specified".to_string(),
                risk_level: RiskLevel::Medium,
            };

            let company = CompanyProfile::new(
                tax_id.unwrap_or_else(|| "TEMP001".to_string()),
                name,
                jurisdiction.into(),
                industry,
            );

            let output_path =
                output.unwrap_or_else(|| PathBuf::from(format!("company_{}.json", company.id)));

            let json = serde_json::to_string_pretty(&company)
                .context("Failed to serialize company profile")?;

            fs::write(&output_path, json)
                .with_context(|| format!("Failed to write to {:?}", output_path))?;

            println!();
            println!("{}", "✅ Company profile created successfully!".green());
            println!("  📁 File: {}", output_path.display());
            println!("  🆔 ID: {}", company.id);
            println!("  📍 Jurisdiction: {:?}", company.jurisdiction);
            println!(
                "  🚫 Excluded jurisdictions: {}",
                company.excluded_jurisdictions.len()
            );
        }

        Commands::Prove {
            proof_type,
            jurisdiction,
            period_days,
            sanctions_lists,
            company_file,
            output,
            auditor,
        } => {
            let pb = ProgressBar::new(4);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );

            pb.set_message("Loading company profile...");
            let company_path =
                company_file.unwrap_or_else(|| PathBuf::from("company_TEMP001.json"));

            let company_data = fs::read_to_string(&company_path)
                .with_context(|| format!("Failed to read {:?}", company_path))?;

            let company: CompanyProfile = serde_json::from_str(&company_data)
                .with_context(|| format!("Failed to parse {:?}", company_path))?;

            pb.inc(1);
            pb.set_message("Loading sanctions database...");

            let prover = ComplianceProver::new(cli.sanctions_db.to_str().unwrap())
                .context("Failed to create compliance prover")?;

            pb.inc(1);
            pb.set_message("Generating proof...");

            let transactions = create_test_transactions(&company);

            let now = Utc::now().timestamp();
            let period_start = now - (period_days as i64 * 24 * 3600);

            let proof = match proof_type {
                ProofType::NoOperations => {
                    let target_jurisdiction = jurisdiction
                        .ok_or_else(|| {
                            anyhow::anyhow!("Jurisdiction required for NoOperations proof")
                        })?
                        .into();

                    prover.prove_no_operations(
                        &company,
                        &transactions,
                        target_jurisdiction,
                        period_start,
                        now,
                    )?
                }

                ProofType::AllScreened => prover.prove_counterparty_screening(
                    &company,
                    sanctions_lists.clone(),
                    period_start,
                )?,

                ProofType::WithinLimits => {
                    let target_jurisdiction = jurisdiction
                        .ok_or_else(|| {
                            anyhow::anyhow!("Jurisdiction required for WithinLimits proof")
                        })?
                        .into();

                    prover.prove_transaction_limits(
                        &company,
                        &transactions,
                        target_jurisdiction,
                        period_start,
                        now,
                    )?
                }

                ProofType::FullCompliance => {
                    let auditor_signature = auditor.as_ref().map(|_| vec![0u8; 64]);

                    prover.create_full_compliance_report(
                        &company,
                        &transactions,
                        sanctions_lists.clone(),
                        auditor_signature,
                    )?
                }

                ProofType::InternalControls => {
                    // TODO: Implement internal controls proof
                    return Err(anyhow::anyhow!(
                        "Internal controls proof not implemented yet"
                    ));
                }
            };

            pb.inc(1);
            pb.set_message("Saving proof...");
            fn fun_name(proof_type: &ProofType, jurisdiction: Option<CountryArg>) -> PathBuf {
                let proof_type_str = match *proof_type {
                    ProofType::NoOperations => "no_ops",
                    ProofType::AllScreened => "screened",
                    ProofType::WithinLimits => "limits",
                    ProofType::FullCompliance => "full",
                    ProofType::InternalControls => "internal",
                };

                let jur_suffix = jurisdiction
                    .map(|j| format!("_{:?}", j))
                    .unwrap_or_default();

                PathBuf::from(format!(
                    "proof_{}{}_{}.json",
                    proof_type_str,
                    jur_suffix,
                    Utc::now().format("%Y%m%d_%H%M%S")
                ))
            }

            let output_path = output.unwrap_or_else(|| fun_name(&proof_type, jurisdiction));

            let json = serde_json::to_string_pretty(&proof).context("Failed to serialize proof")?;

            fs::write(&output_path, json)
                .with_context(|| format!("Failed to write to {:?}", output_path))?;

            pb.finish_with_message("Done!");

            println!();
            println!("{}", "✅ Compliance proof generated successfully!".green());
            println!("  📁 Proof file: {}", output_path.display());
            println!("  🏢 Company: {}", company.name);
            println!("  🔍 Proof type: {:?}", proof_type);

            if let Some(jur) = jurisdiction {
                println!("  📍 Jurisdiction: {:?}", jur);
            }

            println!("  📅 Period: {} days", period_days);
            println!("  📊 Sanctions lists: {}", sanctions_lists.join(", "));

            if let Some(auditor_name) = auditor {
                println!("  🧾 Auditor: {}", auditor_name);
            }
        }

        Commands::Verify {
            proof_file,
            company_file,
            detailed,
        } => {
            println!("{}", "🔍 Verifying compliance proof".cyan().bold());
            println!("  Proof file: {}", proof_file.display());

            let pb = ProgressBar::new(3);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] {msg}")
                    .unwrap(),
            );

            pb.set_message("Loading proof...");
            let proof_data = fs::read_to_string(&proof_file)
                .with_context(|| format!("Failed to read {:?}", proof_file))?;

            let proof: ComplianceProof = serde_json::from_str(&proof_data)
                .with_context(|| format!("Failed to parse {:?}", proof_file))?;

            pb.inc(1);
            pb.set_message("Loading sanctions database...");

            let prover = ComplianceProver::new(cli.sanctions_db.to_str().unwrap())
                .context("Failed to create compliance prover")?;

            pb.inc(1);
            pb.set_message("Verifying proof...");

            let is_valid = prover
                .verify_proof(&proof)
                .context("Proof verification failed")?;

            pb.finish_with_message("Done!");

            println!();

            if is_valid {
                println!("{}", "✅ Proof is VALID".green().bold());

                if detailed {
                    print_proof_details(&proof, company_file.as_deref())?;
                }
            } else {
                println!("{}", "❌ Proof is INVALID".red().bold());
                std::process::exit(1);
            }
        }

        Commands::Audit {
            company_file,
            lists,
            #[allow(unused_variables)]
            output,
        } => {
            println!(
                "{}",
                "🔎 Auditing company against sanctions lists"
                    .yellow()
                    .bold()
            );
            println!("  Company: {}", company_file.display());
            println!("  Lists: {}", lists.join(", "));

            println!();
            println!("{}", "🚧 Audit feature coming soon...".yellow());
            println!();
            println!("Planned checks:");
            println!("  • Verify all counterparties against specified lists");
            println!("  • Check transactions with prohibited jurisdictions");
            println!("  • Validate internal controls and procedures");
            println!("  • Generate audit report with findings");
        }

        Commands::AddCounterparty {
            company_file,
            identifier,
            name,
            jurisdiction,
            counterparty_type,
            check_lists,
            result,
        } => {
            println!(
                "{}",
                "👥 Adding counterparty to company profile".blue().bold()
            );

            let mut company_data = fs::read_to_string(&company_file)
                .with_context(|| format!("Failed to read {:?}", company_file))?;

            let mut company: CompanyProfile = serde_json::from_str(&company_data)
                .with_context(|| format!("Failed to parse {:?}", company_file))?;

            let id_hash = hash_identifier(&identifier);
            let name_hash = name.map(|n| hash_name(&n));

            let check = CounterpartyCheck {
                id_hash,
                name_hash,
                jurisdiction: jurisdiction.into(),
                counterparty_type: counterparty_type.into(),
                check_timestamp: Utc::now(),
                sanctions_lists: check_lists.clone(),
                result: result.map(|r| r.into()).unwrap_or(CheckResult::Clear),
                auditor_id: None,
                auditor_signature: None,
                notes: None,
            };

            company.add_counterparty(check);

            company_data = serde_json::to_string_pretty(&company)
                .context("Failed to serialize updated company profile")?;

            fs::write(&company_file, company_data)
                .with_context(|| format!("Failed to write to {:?}", company_file))?;

            let result_display = result
                .map(|r| format!("{:?}", r))
                .unwrap_or_else(|| "CLEAR".to_string());

            println!();
            println!("{}", "✅ Counterparty added successfully!".green());
            println!("  🏢 Company: {}", company.name);
            println!("  👤 Counterparty: {}", identifier);
            println!("  📍 Jurisdiction: {:?}", jurisdiction);
            println!("  🔍 Type: {:?}", counterparty_type);
            println!("  📋 Checked lists: {}", check_lists.join(", "));
            println!("  ✅ Result: {}", result_display);
            println!(
                "  📊 Total counterparties: {}",
                company.counterparties.len()
            );
        }

        Commands::Status {
            company_file,
            show_counterparties,
        } => {
            let company_data = fs::read_to_string(&company_file)
                .with_context(|| format!("Failed to read {:?}", company_file))?;

            let company: CompanyProfile = serde_json::from_str(&company_data)
                .with_context(|| format!("Failed to parse {:?}", company_file))?;

            println!("{}", "📊 Company Compliance Status".cyan().bold());
            println!();

            let mut table = Table::new();
            table.add_row(row!["🏢 Company", &company.name]);
            table.add_row(row!["🆔 ID", &company.id]);
            table.add_row(row![
                "📍 Jurisdiction",
                format!("{:?}", company.jurisdiction)
            ]);
            table.add_row(row!["🏭 Industry", &company.industry.code]);
            table.add_row(row![
                "📅 Created",
                company.created_at.format("%Y-%m-%d").to_string()
            ]);
            table.add_row(row![
                "📅 Updated",
                company.updated_at.format("%Y-%m-%d").to_string()
            ]);
            table.add_row(row![
                "🚫 Excluded jurisdictions",
                company.excluded_jurisdictions.len()
            ]);
            table.add_row(row![
                "👥 Screened counterparties",
                company.counterparties.len()
            ]);

            let mut clear_count = 0;
            let mut partial_count = 0;
            let mut blocked_count = 0;

            for counterparty in &company.counterparties {
                match counterparty.result {
                    CheckResult::Clear => clear_count += 1,
                    CheckResult::PartialMatch => partial_count += 1,
                    CheckResult::Blocked => blocked_count += 1,
                    CheckResult::Error => {}
                }
            }

            table.add_row(row![
                "✅ Clear counterparties",
                if clear_count > 0 {
                    clear_count.to_string().green()
                } else {
                    "0".normal()
                }
            ]);

            table.add_row(row![
                "⚠️ Partial matches",
                if partial_count > 0 {
                    partial_count.to_string().yellow()
                } else {
                    "0".normal()
                }
            ]);

            table.add_row(row![
                "❌ Blocked counterparties",
                if blocked_count > 0 {
                    blocked_count.to_string().red()
                } else {
                    "0".normal()
                }
            ]);

            table.printstd();

            if show_counterparties && !company.counterparties.is_empty() {
                println!();
                println!("{}", "👥 Counterparty Details".cyan().bold());

                let mut cp_table = Table::new();
                cp_table.add_row(row![
                    "ID Hash",
                    "Jurisdiction",
                    "Type",
                    "Last Check",
                    "Result",
                    "Lists Checked"
                ]);

                for (i, cp) in company.counterparties.iter().enumerate() {
                    if i >= 10 {
                        cp_table.add_row(row!["...", "...", "...", "...", "...", "..."]);
                        break;
                    }

                    let id_short = hex::encode(&cp.id_hash[..8]);
                    let result_str = match cp.result {
                        CheckResult::Clear => "✅ CLEAR".green(),
                        CheckResult::PartialMatch => "⚠️ PARTIAL".yellow(),
                        CheckResult::Blocked => "❌ BLOCKED".red(),
                        CheckResult::Error => "❓ ERROR".red(),
                    };

                    cp_table.add_row(row![
                        id_short,
                        format!("{:?}", cp.jurisdiction),
                        format!("{:?}", cp.counterparty_type),
                        cp.check_timestamp.format("%Y-%m-%d").to_string(),
                        result_str,
                        cp.sanctions_lists.join(", ")
                    ]);
                }

                cp_table.printstd();
            }
        }

        Commands::GenerateTestData {
            #[allow(unused_variables)]
            companies,
            #[allow(unused_variables)]
            transactions,
            output_dir,
        } => {
            println!("{}", "🧪 Generating test data".magenta().bold());

            if !output_dir.exists() {
                fs::create_dir_all(&output_dir)
                    .with_context(|| format!("Failed to create directory {:?}", output_dir))?;
            }

            // TODO: Implement test data generation
            println!("🚧 Test data generation coming soon...");
        }
    }

    Ok(())
}

fn create_test_transactions(_company: &CompanyProfile) -> Vec<szip_rescomply_core::Transaction> {

    vec![
        szip_rescomply_core::Transaction {
            id: "TEST_TX_001".to_string(),
            timestamp: Utc::now() - Duration::days(10),
            amount: 1_000_000_00,
            currency: "RUB".to_string(),
            counterparty_hash: [1u8; 32],
            counterparty_jurisdiction: Jurisdiction::RU,
            purpose: Some("Payment for software development".to_string()),
            category: szip_rescomply_core::TransactionCategory::ServicesPayment,
            amount_commitment: None,
            nullifier: None,
        },
        szip_rescomply_core::Transaction {
            id: "TEST_TX_002".to_string(),
            timestamp: Utc::now() - Duration::days(5),
            amount: 500_000_00,
            currency: "USD".to_string(),
            counterparty_hash: [2u8; 32],
            counterparty_jurisdiction: Jurisdiction::US,
            purpose: Some("Cloud services subscription".to_string()),
            category: szip_rescomply_core::TransactionCategory::ServicesPayment,
            amount_commitment: None,
            nullifier: None,
        },
    ]
}

fn print_proof_details(
    proof: &ComplianceProof,
    company_file: Option<&std::path::Path>,
) -> Result<()> {
    match proof {
        ComplianceProof::NoOperationsWith {
            jurisdiction,
            period_start,
            period_end,
            transaction_count,
            ..
        } => {
            println!();
            println!("{}", "📋 Proof Details".cyan());
            println!("  Type: No operations with jurisdiction");
            println!("  Jurisdiction: {:?}", jurisdiction);
            println!(
                "  Period: {} - {}",
                DateTime::from_timestamp(*period_start, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| period_start.to_string()),
                DateTime::from_timestamp(*period_end, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| period_end.to_string()),
            );
            println!("  Transactions analyzed: {}", transaction_count);
        }

        ComplianceProof::AllCounterpartiesScreened {
            sanctions_lists,
            screening_timestamp,
            total_counterparties,
            blocked_counterparties,
            ..
        } => {
            println!();
            println!("{}", "📋 Proof Details".cyan());
            println!("  Type: All counterparties screened");
            println!("  Sanctions lists: {}", sanctions_lists.join(", "));
            println!(
                "  Screening date: {}",
                DateTime::from_timestamp(*screening_timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| screening_timestamp.to_string())
            );
            println!("  Total counterparties: {}", total_counterparties);
            println!("  Blocked counterparties: {}", blocked_counterparties);

            if *blocked_counterparties > 0 {
                println!(
                    "  {}",
                    "⚠️  WARNING: Blocked counterparties found!".yellow()
                );
            }
        }

        ComplianceProof::TransactionLimitsRespected {
            jurisdiction,
            max_allowed_amount,
            period_start,
            period_end,
            transaction_count,
            ..
        } => {
            println!();
            println!("{}", "📋 Proof Details".cyan());
            println!("  Type: Transaction limits respected");
            println!("  Jurisdiction: {:?}", jurisdiction);
            println!(
                "  Max allowed amount: {:.2}",
                *max_allowed_amount as f64 / 100.0
            );
            println!(
                "  Period: {} - {}",
                DateTime::from_timestamp(*period_start, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| period_start.to_string()),
                DateTime::from_timestamp(*period_end, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| period_end.to_string()),
            );
            println!("  Transactions in period: {}", transaction_count);
        }

        ComplianceProof::FullComplianceReport {
            report_timestamp,
            proofs,
            ..
        } => {
            println!();
            println!("{}", "📋 Full Compliance Report".cyan());
            println!(
                "  Report date: {}",
                DateTime::from_timestamp(*report_timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| report_timestamp.to_string())
            );
            println!("  Included proofs: {}", proofs.len());

            for (i, proof) in proofs.iter().enumerate() {
                println!("    {}. {:?}", i + 1, std::mem::discriminant(proof));
            }
        }

        _ => {
            println!("  Proof type: {:?}", std::mem::discriminant(proof));
        }
    }

    if let Some(company_file) = company_file {
        if let Ok(company_data) = fs::read_to_string(company_file) {
            if let Ok(parsed_company) = serde_json::from_str::<CompanyProfile>(&company_data) {
                println!();
                println!("{}", "🏢 Related Company".cyan());
                println!("  Name: {}", parsed_company.name);
                println!("  ID: {}", parsed_company.id);
                println!("  Jurisdiction: {:?}", parsed_company.jurisdiction);
            }
        }
    }

    Ok(())
}
