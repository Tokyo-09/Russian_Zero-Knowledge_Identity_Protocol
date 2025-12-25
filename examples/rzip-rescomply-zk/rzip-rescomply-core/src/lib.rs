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

// ISO 3166-1 alpha-2 страны + расширения для санкций
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Jurisdiction {
    // Основные страны
    RU, // Россия
    US, // США
    GB, // Великобритания
    DE, // Германия
    CN, // Китай
    BY, // Беларусь
    
    // Санкционные регионы
    Crimea,   // Крым (UA-43)
    Donetsk,  // ДНР (UA-14)
    Luhansk,  // ЛНР (UA-09)
    
    // Страны под санкциями
    IR, // Иран
    SY, // Сирия
    KP, // Северная Корея
    CU, // Куба
    VE, // Венесуэла
    
    // Офшорные зоны
    BVI,    // Британские Виргинские острова
    Cayman, // Каймановы острова
    Panama, // Панама
    Bermuda,// Бермуды
    Jersey, // Джерси
    
    // Специальные коды
    World,  // Весь мир (для общих запретов)
    Unknown,// Неизвестная юрисдикция
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

// Отрасль компании (ОКВЭД/NACE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndustryCode {
    pub code: String,           // Например "62.01"
    pub description: String,    // "Разработка программного обеспечения"
    pub risk_level: RiskLevel,  // Уровень риска для AML/CFT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,     // Низкий риск
    Medium,  // Средний риск
    High,    // Высокий риск
    Prohibited, // Запрещённая деятельность
}

// Санкционный список
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsList {
    pub id: String,                     // "OFAC-SDN-2024-01"
    pub authority: String,              // "OFAC", "EU", "Rosfinmonitoring"
    pub version: u32,
    pub effective_from: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    
    // Запрещённые юрисдикции
    pub prohibited_jurisdictions: Vec<Jurisdiction>,
    
    // Хеши запрещённых лиц/компаний
    pub entity_hashes: Vec<[u8; 32]>,
    pub individual_hashes: Vec<[u8; 32]>,
    
    // Категории санкций
    pub categories: Vec<SanctionCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanctionCategory {
    Financial,     // Финансовые санкции
    Trade,         // Торговые ограничения
    Travel,        // Запрет на въезд
    ArmsEmbargo,   // Эмбарго на оружие
    Sectoral,      // Секторальные санкции
}

// Результат проверки контрагента
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckResult {
    Clear,          // Чист
    PartialMatch,   // Частичное совпадение (требует ручной проверки)
    Blocked,        // В санкционных списках
    Error,          // Ошибка проверки
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

// Проверка контрагента
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterpartyCheck {
    pub id_hash: [u8; 32],             // SHA3-256 хеш идентификатора
    pub name_hash: Option<[u8; 32]>,   // Хеш имени (опционально)
    pub jurisdiction: Jurisdiction,
    pub counterparty_type: CounterpartyType,
    
    pub check_timestamp: DateTime<Utc>,
    pub sanctions_lists: Vec<String>,  // Какие списки проверены
    pub result: CheckResult,
    
    pub auditor_id: Option<String>,    // ID аудитора
    pub auditor_signature: Option<Vec<u8>>,
    pub notes: Option<String>,         // Примечания по проверке
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CounterpartyType {
    Supplier,       // Поставщик
    Customer,       // Клиент
    Bank,           // Банк-корреспондент
    Subsidiary,     // Дочерняя компания
    Shareholder,    // Акционер (>5%)
    Director,       // Руководитель
    Employee,       // Сотрудник (key personnel)
    Other,          // Другое
}

// Транзакция
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub amount: u64,                    // В минимальных единицах (копейки, центы)
    pub currency: String,               // RUB, USD, EUR, CNY
    
    pub counterparty_hash: [u8; 32],    // Хеш контрагента
    pub counterparty_jurisdiction: Jurisdiction,
    
    pub purpose: Option<String>,        // Назначение платежа
    pub category: TransactionCategory,
    
    // Для ZK proofs
    pub amount_commitment: Option<[u8; 32]>, // Pedersen commitment к сумме
    pub nullifier: Option<[u8; 32]>,         // Для предотвращения двойного учёта
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionCategory {
    GoodsPayment,      // Оплата товаров
    ServicesPayment,   // Оплата услуг
    Dividend,          // Дивиденды
    Loan,              // Заём
    Investment,        // Инвестиции
    TaxPayment,        // Налоги
    Salary,            // Зарплата
    Other,             // Другое
}

// Профиль компании
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyProfile {
    // Идентификация
    pub id: String,                     // LEI, ИНН, или внутренний ID
    pub name: String,
    pub jurisdiction: Jurisdiction,
    pub registration_number: String,    // ОГРН, EIN и т.д.
    pub tax_id: String,                 // ИНН, VAT и т.д.
    
    // Отрасль и деятельность
    pub industry: IndustryCode,
    pub description: String,
    
    // Compliance политика
    pub compliance_policy_hash: [u8; 32],    // Хеш compliance-политики
    pub risk_assessment_hash: [u8; 32],      // Хеш оценки рисков
    pub kyc_procedure_hash: [u8; 32],        // Хеш процедуры KYC
    
    // Санкционные обязательства (публичные)
    pub excluded_jurisdictions: Vec<Jurisdiction>,
    pub max_transaction_amounts: HashMap<Jurisdiction, u64>, // Лимиты по юрисдикциям
    pub prohibited_counterparty_types: Vec<CounterpartyType>,
    
    // Приватные данные (для генерации proof'ов)
    pub counterparties: Vec<CounterpartyCheck>,
    pub transactions_hash: [u8; 32],         // Корень меркле-дерева транзакций
    pub blacklist_hash: [u8; 32],            // Хеш внутреннего чёрного списка
    pub audit_trail_hash: [u8; 32],          // Хеш логов аудита
    
    // Метаданные
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub compliance_officer: Option<String>,  // Ответственный за compliance
    pub auditor_firm: Option<String>,        // Аудиторская фирма
}

impl CompanyProfile {
    /// Создать новый профиль компании
    pub fn new(
        id: String,
        name: String,
        jurisdiction: Jurisdiction,
        industry: IndustryCode,
    ) -> Self {
        let now = Utc::now();
        
        // Базовые исключения (можно настраивать)
        let excluded_jurisdictions = vec![
            Jurisdiction::Crimea,
            Jurisdiction::Donetsk,
            Jurisdiction::Luhansk,
            Jurisdiction::IR,
            Jurisdiction::SY,
            Jurisdiction::KP,
        ];
        
        // Базовые лимиты транзакций
        let mut max_transaction_amounts = HashMap::new();
        max_transaction_amounts.insert(Jurisdiction::BVI, 10_000_000_00); // 10M в копейках
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
    
    /// Добавить проверенного контрагента
    pub fn add_counterparty(&mut self, check: CounterpartyCheck) {
        self.counterparties.push(check);
        self.updated_at = Utc::now();
    }
    
    /// Хешировать данные компании для фиксации состояния
    pub fn compute_state_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        
        // Хешируем важные поля
        hasher.update(&self.id);
        hasher.update(&self.name);
        hasher.update(format!("{:?}", self.jurisdiction));
        hasher.update(&self.industry.code);
        
        // Хешируем списки исключений
        for jur in &self.excluded_jurisdictions {
            hasher.update(format!("{:?}", jur));
        }
        
        // Хешируем проверенных контрагентов
        for counterparty in &self.counterparties {
            hasher.update(&counterparty.id_hash);
            hasher.update(format!("{:?}", counterparty.result));
        }
        
        hasher.finalize().into()
    }
    
    /// Проверить соответствие публичным обязательствам
    pub fn validate_commitments(&self) -> Result<(), ComplianceError> {
        // Проверяем что все исключённые юрисдикции действительно исключены
        // (в реальной реализации здесь была бы проверка транзакций)
        
        // Проверяем что все контрагенты проверены
        for counterparty in &self.counterparties {
            if counterparty.result == CheckResult::Blocked {
                return Err(ComplianceError::CounterpartyCheckFailed(
                    format!("Blocked counterparty found: {:?}", counterparty.id_hash)
                ));
            }
        }
        
        Ok(())
    }
}

// Утилитарные функции
pub fn hash_identifier(identifier: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(identifier.as_bytes());
    hasher.finalize().into()
}

pub fn hash_name(name: &str) -> [u8; 32] {
    // Нормализуем имя: uppercase, удаляем лишние пробелы
    let normalized = name.to_uppercase()
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
        assert!(company.excluded_jurisdictions.contains(&Jurisdiction::Crimea));
        assert!(company.max_transaction_amounts.contains_key(&Jurisdiction::BVI));
    }
    
    #[test]
    fn test_hashing() {
        let hash = hash_identifier("ООО Рога и Копыта");
        assert_eq!(hash.len(), 32);
        
        let hash2 = hash_identifier("ООО РОГА И КОПЫТА"); // Должно быть то же самое
        assert_eq!(hash, hash2);
    }
}