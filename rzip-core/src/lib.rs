use std::fmt;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did {
    pub method: String,
    pub identifier: String,
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "did:{}:{}", self.method, self.identifier)
    }
}

impl Did {
    pub fn new(method: &str, id: &str) -> Result<Self> {
        if method.is_empty() || id.is_empty() {
            return Err(anyhow!("DID method and identifier must be non-empty"));
        }
        if method.contains(':') || id.contains(':') {
            return Err(anyhow!("DID method or identifier must not contain ':'"));
        }
        Ok(Did {
            method: method.to_string(),
            identifier: id.to_string(),
        })
    }

    /*
    pub fn to_string(&self) -> String {
        format!()
    }
    */

    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 || parts[0] != "did" {
            return Err(anyhow!("Invalid DID format: expected did:<method>:<id>"));
        }
        Did::new(parts[1], parts[2])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub subject: Did,
    pub attribute: String,
    pub value_commitment: [u8; 32],
    pub min_value: u8,
    pub max_value: u8,
    pub issued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub issuer: Did,
    pub claim: Claim,
}
