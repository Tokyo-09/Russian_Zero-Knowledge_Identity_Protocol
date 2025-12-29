use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ComplianceError {
    #[error("Invalid jurisdiction: {0}")]
    InvalidJurisdiction(String),

    #[error("Sanctions list not found: {0}")]
    SanctionsListNotFound(String),

    #[error("Counterparty check failed: {0}")]
    CounterpartyCheckFailed(String),

    #[error("Transaction limit exceeded: {0}")]
    TransactionLimitExceeded(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Jurisdiction {
    RU,
    US,
    GB, 
    DE,
    CN, 
    BY,

    Crimea,  
    Donetsk, 
    Luhansk,

    IR, 
    SY, 
    KP, 
    CU, 
    VE, 

    BVI,     
    Cayman,  
    Panama,  
    Bermuda, 
    Jersey,  

    World,  
    Unknown,
}

impl std::fmt::Display for Jurisdiction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<&str> for Jurisdiction {
    type Error = ComplianceError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_uppercase().as_str() {
            "RU" => Ok(Jurisdiction::RU),
            "US" => Ok(Jurisdiction::US),
            "GB" => Ok(Jurisdiction::GB),
            "DE" => Ok(Jurisdiction::DE),
            "CN" => Ok(Jurisdiction::CN),
            "BY" => Ok(Jurisdiction::BY),
            "CRIMEA" => Ok(Jurisdiction::Crimea),
            "DONETSK" => Ok(Jurisdiction::Donetsk),
            "LUHANSK" => Ok(Jurisdiction::Luhansk),
            "IR" => Ok(Jurisdiction::IR),
            "SY" => Ok(Jurisdiction::SY),
            "KP" => Ok(Jurisdiction::KP),
            "CU" => Ok(Jurisdiction::CU),
            "VE" => Ok(Jurisdiction::VE),
            "BVI" => Ok(Jurisdiction::BVI),
            "CAYMAN" => Ok(Jurisdiction::Cayman),
            "PANAMA" => Ok(Jurisdiction::Panama),
            "BERMUDA" => Ok(Jurisdiction::Bermuda),
            "JERSEY" => Ok(Jurisdiction::Jersey),
            "WORLD" => Ok(Jurisdiction::World),
            "UNKNOWN" => Ok(Jurisdiction::Unknown),
            _ => Err(ComplianceError::InvalidJurisdiction(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndustryCode {
    pub code: String,        
    pub description: String,   
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,     
    Medium,     
    High,      
    Prohibited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsList {
    pub id: String,     
    pub authority: String,
    pub version: u32,
    pub effective_from: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,

    pub prohibited_jurisdictions: Vec<Jurisdiction>,

    pub entity_hashes: Vec<[u8; 32]>,
    pub individual_hashes: Vec<[u8; 32]>,

    pub categories: Vec<SanctionCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanctionCategory {
    Financial, 
    Trade,     
    Travel,    
    ArmsEmbargo, 
    Sectoral,   
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckResult {
    Clear,        
    PartialMatch, 
    Blocked,      
    Error,        
}

impl std::fmt::Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckResult::Clear => write!(f, "CLEAR"),
            CheckResult::PartialMatch => write!(f, "PARTIAL_MATCH"),
            CheckResult::Blocked => write!(f, "BLOCKED"),
            CheckResult::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterpartyCheck {
    pub id_hash: [u8; 32],         
    pub name_hash: Option<[u8; 32]>,
    pub jurisdiction: Jurisdiction,
    pub counterparty_type: CounterpartyType,

    pub check_timestamp: DateTime<Utc>,
    pub sanctions_lists: Vec<String>,
    pub result: CheckResult,

    pub auditor_id: Option<String>, 
    pub auditor_signature: Option<Vec<u8>>,
    pub notes: Option<String>, 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CounterpartyType {
    Supplier,   
    Customer,   
    Bank,       
    Subsidiary, 
    Shareholder,
    Director,   
    Employee,   
    Other,     
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub amount: u64,     
    pub currency: String, 

    pub counterparty_hash: [u8; 32], 
    pub counterparty_jurisdiction: Jurisdiction,

    pub purpose: Option<String>, 
    pub category: TransactionCategory,

    pub amount_commitment: Option<[u8; 32]>, 
    pub nullifier: Option<[u8; 32]>,         
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionCategory {
    GoodsPayment,    
    ServicesPayment, 
    Dividend,        
    Loan,            
    Investment,      
    TaxPayment,      
    Salary,          
    Other,           
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyProfile {
    pub id: String,
    pub name: String,
    pub jurisdiction: Jurisdiction,
    pub registration_number: String, 
    pub tax_id: String,             

    pub industry: IndustryCode,
    pub description: String,

    pub compliance_policy_hash: [u8; 32],
    pub risk_assessment_hash: [u8; 32],  
    pub kyc_procedure_hash: [u8; 32],    

    pub excluded_jurisdictions: Vec<Jurisdiction>,
    pub max_transaction_amounts: HashMap<Jurisdiction, u64>,
    pub prohibited_counterparty_types: Vec<CounterpartyType>,

    pub counterparties: Vec<CounterpartyCheck>,
    pub transactions_hash: [u8; 32],
    pub blacklist_hash: [u8; 32],   
    pub audit_trail_hash: [u8; 32],

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub compliance_officer: Option<String>,
    pub auditor_firm: Option<String>,      
}

impl CompanyProfile {
    pub fn new(
        id: String,
        name: String,
        jurisdiction: Jurisdiction,
        industry: IndustryCode,
    ) -> Self {
        let now = Utc::now();

        let excluded_jurisdictions = vec![
            Jurisdiction::Crimea,
            Jurisdiction::Donetsk,
            Jurisdiction::Luhansk,
            Jurisdiction::IR,
            Jurisdiction::SY,
            Jurisdiction::KP,
        ];

        let mut max_transaction_amounts = HashMap::new();
        max_transaction_amounts.insert(Jurisdiction::BVI, 10_000_000_00);
        max_transaction_amounts.insert(Jurisdiction::Cayman, 5_000_000_00);
        max_transaction_amounts.insert(Jurisdiction::Panama, 2_000_000_00);

        Self {
            id,
            name,
            jurisdiction,
            registration_number: String::new(),
            tax_id: String::new(),
            industry,
            description: String::new(),

            compliance_policy_hash: [0u8; 32],
            risk_assessment_hash: [0u8; 32],
            kyc_procedure_hash: [0u8; 32],

            excluded_jurisdictions,
            max_transaction_amounts,
            prohibited_counterparty_types: vec![],

            counterparties: vec![],
            transactions_hash: [0u8; 32],
            blacklist_hash: [0u8; 32],
            audit_trail_hash: [0u8; 32],

            created_at: now,
            updated_at: now,
            compliance_officer: None,
            auditor_firm: None,
        }
    }

    pub fn add_counterparty(&mut self, check: CounterpartyCheck) {
        self.counterparties.push(check);
        self.updated_at = Utc::now();
    }

    pub fn compute_state_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        hasher.update(&self.id);
        hasher.update(&self.name);
        hasher.update(format!("{:?}", self.jurisdiction));
        hasher.update(&self.industry.code);

        for jur in &self.excluded_jurisdictions {
            hasher.update(format!("{:?}", jur));
        }

        for counterparty in &self.counterparties {
            hasher.update(&counterparty.id_hash);
            hasher.update(format!("{:?}", counterparty.result));
        }

        hasher.finalize().into()
    }

    pub fn validate_commitments(&self) -> Result<(), ComplianceError> {

        for counterparty in &self.counterparties {
            if counterparty.result == CheckResult::Blocked {
                return Err(ComplianceError::CounterpartyCheckFailed(format!(
                    "Blocked counterparty found: {:?}",
                    counterparty.id_hash
                )));
            }
        }

        Ok(())
    }
}

pub fn hash_identifier(identifier: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(identifier.as_bytes());
    hasher.finalize().into()
}

pub fn hash_name(name: &str) -> [u8; 32] {
    let normalized = name
        .to_uppercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut hasher = Sha3_256::new();
    hasher.update(normalized.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jurisdiction_conversion() {
        let jur: Jurisdiction = "RU".try_into().unwrap();
        assert_eq!(jur, Jurisdiction::RU);

        let jur: Jurisdiction = "BVI".try_into().unwrap();
        assert_eq!(jur, Jurisdiction::BVI);
    }

    #[test]
    fn test_company_profile() {
        let industry = IndustryCode {
            code: "62.01".to_string(),
            description: "Разработка программного обеспечения".to_string(),
            risk_level: RiskLevel::Low,
        };

        let company = CompanyProfile::new(
            "1234567890".to_string(),
            "Тестовая компания".to_string(),
            Jurisdiction::RU,
            industry,
        );

        assert_eq!(company.jurisdiction, Jurisdiction::RU);
        assert!(
            company
                .excluded_jurisdictions
                .contains(&Jurisdiction::Crimea)
        );
        assert!(
            company
                .max_transaction_amounts
                .contains_key(&Jurisdiction::BVI)
        );
    }

    #[test]
    fn test_hashing() {
        let hash = hash_identifier("ООО Рога и Копыта");
        assert_eq!(hash.len(), 32);

        let hash2 = hash_identifier("ООО РОГА И КОПЫТА");
        assert_eq!(hash, hash2);
    }
}
