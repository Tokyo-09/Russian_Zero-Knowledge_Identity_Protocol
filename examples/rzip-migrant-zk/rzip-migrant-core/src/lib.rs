use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum RegionCode {
    Moscow = 77,
    SaintPetersburg = 78,
    MoscowOblast = 50,
}

impl RegionCode {
    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            77 => Some(RegionCode::Moscow),
            78 => Some(RegionCode::SaintPetersburg),
            50 => Some(RegionCode::MoscowOblast),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermitType {
    Visa,
    RVP,
    Patent,
    VNJ,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationClaim {
    pub subject_commitment: [u8; 32],
    pub status: Status,
    pub valid_until: DateTime<Utc>,
    pub region: RegionCode,
    pub permit_type: PermitType,
    pub restrictions: Vec<String>, // e.g., ["no_work"]
    pub issuance_date: DateTime<Utc>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Valid,
    Expired,
    Revoked,
}

impl Status {
    pub fn is_valid(&self, _now: DateTime<Utc>) -> bool {
        matches!(self, Status::Valid)
    }
}
