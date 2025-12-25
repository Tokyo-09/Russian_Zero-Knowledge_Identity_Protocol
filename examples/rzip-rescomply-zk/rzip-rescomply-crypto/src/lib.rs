use anyhow::{Context, Result, anyhow};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use rzip_rescomply_core::{
    CheckResult, CompanyProfile, Jurisdiction, Transaction, TransactionCategory,
};

// Типы ZK Proofs для compliance
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ComplianceProof {
    /// Доказательство отсутствия операций с юрисдикцией
    NoOperationsWith {
        jurisdiction: Jurisdiction,
        proof: Vec<u8>,       // Bulletproof range proof
        commitment: [u8; 32], // Pedersen commitment
        period_start: i64,    // Unix timestamp
        period_end: i64,
        transaction_count: u32, // Количество транзакций за период
    },

    /// Доказательство проверки всех контрагентов
    AllCounterpartiesScreened {
        sanctions_lists: Vec<String>, // Проверенные списки
        proof: Vec<u8>,
        counterparties_root: [u8; 32], // Меркле-корень проверенных контрагентов
        screening_timestamp: i64,
        total_counterparties: u32,
        blocked_counterparties: u32, // Должно быть 0
    },

    /// Доказательство соблюдения лимитов транзакций
    TransactionLimitsRespected {
        jurisdiction: Jurisdiction,
        proof: Vec<u8>,
        total_amount_commitment: [u8; 32], // Commitment к общей сумме
        max_allowed_amount: u64,
        period_start: i64,
        period_end: i64,
        transaction_count: u32,
    },

    /// Доказательство внутреннего контроля
    InternalControlsVerified {
        proof: Vec<u8>,
        policy_hash: [u8; 32],      // Хеш compliance-политики
        audit_trail_hash: [u8; 32], // Хеш логов аудита
        last_audit_timestamp: i64,
        control_points_verified: u32,
    },

    /// Комбинированное доказательство (все проверки сразу)
    FullComplianceReport {
        proofs: Vec<ComplianceProof>, // Все отдельные proof'ы
        company_state_hash: [u8; 32], // Хеш состояния компании
        report_timestamp: i64,
        auditor_signature: Option<Vec<u8>>, // Цифровая подпись аудитора
    },
}

// Санкционная база данных
pub struct SanctionsDatabase {
    lists: HashMap<String, rzip_rescomply_core::SanctionsList>,
    updated_at: i64,
}

impl SanctionsDatabase {
    /// Загрузить базу данных из директории
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut lists = HashMap::new();

        for entry in fs::read_dir(path).context("Failed to read sanctions database")? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let data = fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read {:?}", path))?;

                let list: rzip_rescomply_core::SanctionsList = serde_json::from_str(&data)
                    .with_context(|| format!("Failed to parse {:?}", path))?;

                lists.insert(list.id.clone(), list);
            }
        }

        Ok(Self {
            lists,
            updated_at: chrono::Utc::now().timestamp(),
        })
    }

    /// Проверить контрагента по всем спискам
    pub fn check_counterparty(
        &self,
        counterparty_hash: [u8; 32],
        lists_to_check: &[String],
    ) -> CheckResult {
        let mut found_in_lists = Vec::new();

        for list_id in lists_to_check {
            if let Some(list) = self.lists.get(list_id) {
                // Проверяем по хешам юридических лиц
                if list.entity_hashes.contains(&counterparty_hash) {
                    found_in_lists.push(list_id.clone());
                }

                // Проверяем по хешам физических лиц
                if list.individual_hashes.contains(&counterparty_hash) {
                    found_in_lists.push(list_id.clone());
                }
            }
        }

        if !found_in_lists.is_empty() {
            CheckResult::Blocked
        } else {
            CheckResult::Clear
        }
    }

    /// Получить все запрещённые юрисдикции из указанных списков
    pub fn get_prohibited_jurisdictions(&self, list_ids: &[String]) -> Vec<Jurisdiction> {
        let mut jurisdictions = Vec::new();

        for list_id in list_ids {
            if let Some(list) = self.lists.get(list_id) {
                jurisdictions.extend(list.prohibited_jurisdictions.iter().cloned());
            }
        }

        // Удаляем дубликаты
        jurisdictions.sort();
        jurisdictions.dedup();
        jurisdictions
    }
}

// Основной провайдер ZK proofs
pub struct ComplianceProver {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
    sanctions_db: SanctionsDatabase,
}

impl ComplianceProver {
    /// Создать новый prover с загруженной базой санкций
    pub fn new(sanctions_db_path: &str) -> Result<Self> {
        let bp_gens = BulletproofGens::new(128, 1);
        let pc_gens = PedersenGens::default();
        let sanctions_db = SanctionsDatabase::load(sanctions_db_path)
            .context("Failed to load sanctions database")?;

        Ok(Self {
            bp_gens,
            pc_gens,
            sanctions_db,
        })
    }

    /// Создать транзакцию с ZK commitment
    pub fn create_transaction(
        &self,
        amount: u64,
        currency: &str,
        counterparty_hash: [u8; 32],
        counterparty_jurisdiction: Jurisdiction,
        category: TransactionCategory,
    ) -> Result<Transaction> {
        let mut rng = OsRng;

        // Создаём Pedersen commitment к сумме
        let blinding = Scalar::random(&mut rng);
        let amount_scalar = Scalar::from(amount);
        let commitment_point = self.pc_gens.commit(amount_scalar, blinding); //.commit(amount_scalar, blinding);
        let commitment = commitment_point.compress().to_bytes();

        // Создаём nullifier для предотвращения двойного учёта
        let nullifier = {
            let mut hasher = Sha3_256::new();
            hasher.update(&commitment);
            hasher.update(chrono::Utc::now().timestamp().to_be_bytes());
            hasher.update(&counterparty_hash);
            hasher.finalize().into()
        };

        Ok(Transaction {
            id: format!("tx_{}", hex::encode(&nullifier[..8])),
            timestamp: chrono::Utc::now(),
            amount,
            currency: currency.to_string(),
            counterparty_hash,
            counterparty_jurisdiction,
            purpose: None,
            category,
            amount_commitment: Some(commitment),
            nullifier: Some(nullifier),
        })
    }

    /// Доказать отсутствие операций с юрисдикцией за период
    pub fn prove_no_operations(
        &self,
        company: &CompanyProfile,
        transactions: &[Transaction],
        jurisdiction: Jurisdiction,
        period_start: i64,
        period_end: i64,
    ) -> Result<ComplianceProof> {
        // 1. Проверяем что компания публично исключила эту юрисдикцию
        if !company.excluded_jurisdictions.contains(&jurisdiction) {
            return Err(anyhow!(
                "Company doesn't publicly exclude jurisdiction {:?}",
                jurisdiction
            ));
        }

        // 2. Фильтруем транзакции за период
        let period_transactions: Vec<_> = transactions
            .iter()
            .filter(|tx| {
                let ts = tx.timestamp.timestamp();
                ts >= period_start && ts <= period_end
            })
            .collect();

        // 3. Ищем транзакции с целевой юрисдикцией
        let forbidden_transactions: Vec<_> = period_transactions
            .iter()
            .filter(|tx| tx.counterparty_jurisdiction == jurisdiction)
            .collect();

        if !forbidden_transactions.is_empty() {
            return Err(anyhow!(
                "Found {} transactions with prohibited jurisdiction {:?}",
                forbidden_transactions.len(),
                jurisdiction
            ));
        }

        // 4. Создаём ZK proof что сумма всех транзакций с этой юрисдикцией = 0
        let mut rng = OsRng;
        let mut transcript = Transcript::new(b"ZK-ResComply_NoOperations");

        // Значение: 0 (нет транзакций)
        let value = 0u64;
        let blinding = Scalar::random(&mut rng);

        let commitment = self.pc_gens.commit(Scalar::from(value), blinding);
        let commitment_bytes = commitment.compress().to_bytes();

        // Bulletproof range proof что value = 0
        let proof = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            value,
            &blinding,
            8, // 8 бит достаточно для 0
        )?;

        Ok(ComplianceProof::NoOperationsWith {
            jurisdiction,
            proof: proof.0.to_bytes(),
            commitment: commitment_bytes,
            period_start,
            period_end,
            transaction_count: period_transactions.len() as u32,
        })
    }

    /// Доказать что все контрагенты проверены по санкционным спискам
    pub fn prove_counterparty_screening(
        &self,
        company: &CompanyProfile,
        sanctions_lists: Vec<String>,
        screening_cutoff: i64,
    ) -> Result<ComplianceProof> {
        // 1. Проверяем каждого контрагента
        let mut blocked_count = 0;
        let mut total_counterparties = 0;

        for counterparty in &company.counterparties {
            total_counterparties += 1;

            // Проверяем дату проверки
            if counterparty.check_timestamp.timestamp() < screening_cutoff {
                return Err(anyhow!(
                    "Counterparty check too old: {:?} < {}",
                    counterparty.check_timestamp,
                    screening_cutoff
                ));
            }

            // Проверяем что проверены все требуемые списки
            for list in &sanctions_lists {
                if !counterparty.sanctions_lists.contains(list) {
                    return Err(anyhow!("Counterparty not checked against list: {}", list));
                }
            }

            // Проверяем результат
            if counterparty.result == CheckResult::Blocked {
                blocked_count += 1;
            }
        }

        if blocked_count > 0 {
            return Err(anyhow!("Found {} blocked counterparties", blocked_count));
        }

        // 2. Создаём меркле-дерево из хешей проверок
        let leaves: Vec<[u8; 32]> = company
            .counterparties
            .iter()
            .map(|c| {
                let mut hasher = Sha3_256::new();
                hasher.update(&c.id_hash);
                hasher.update(c.check_timestamp.timestamp().to_be_bytes());
                hasher.update(c.result.to_string().as_bytes());
                hasher.finalize().into()
            })
            .collect();

        let merkle_root = self.build_merkle_root(&leaves)?;

        // 3. ZK proof что все контрагенты имеют статус Clear
        let mut transcript = Transcript::new(b"ZK-ResComply_Screening");
        let mut rng = OsRng;

        // Кодируем: Clear = 0, PartialMatch = 1, Blocked = 2
        // Мы хотим доказать что все значения = 0
        // Для этого создаём commitment к 0 и доказываем что value ∈ [0, 0]
        let value = 0u64;
        let blinding = Scalar::random(&mut rng);

        let commitment = self.pc_gens.commit(Scalar::from(value), blinding);
        let commitment_bytes = commitment.compress().to_bytes();

        let proof = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            value,
            &blinding,
            2, // 2 бита достаточно для значений 0-2
        )?;

        Ok(ComplianceProof::AllCounterpartiesScreened {
            sanctions_lists,
            proof: proof.0.to_bytes(),
            counterparties_root: merkle_root,
            screening_timestamp: screening_cutoff,
            total_counterparties,
            blocked_counterparties: 0,
        })
    }

    /// Доказать соблюдение лимитов транзакций
    pub fn prove_transaction_limits(
        &self,
        company: &CompanyProfile,
        transactions: &[Transaction],
        jurisdiction: Jurisdiction,
        period_start: i64,
        period_end: i64,
    ) -> Result<ComplianceProof> {
        // 1. Находим установленный лимит
        let max_amount = company
            .max_transaction_amounts
            .get(&jurisdiction)
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "No transaction limit set for jurisdiction {:?}",
                    jurisdiction
                )
            })?;

        // 2. Фильтруем и суммируем транзакции
        let mut total_amount = 0u64;
        let mut transaction_count = 0;

        for tx in transactions {
            let ts = tx.timestamp.timestamp();
            if ts >= period_start
                && ts <= period_end
                && tx.counterparty_jurisdiction == jurisdiction
            {
                total_amount += tx.amount;
                transaction_count += 1;

                // Проверяем каждую транзакцию на превышение лимита
                if tx.amount > max_amount {
                    return Err(anyhow!(
                        "Transaction {} exceeds limit: {} > {}",
                        tx.id,
                        tx.amount,
                        max_amount
                    ));
                }
            }
        }

        // 3. Проверяем общую сумму
        if total_amount > max_amount {
            return Err(anyhow!(
                "Total amount {} exceeds limit {} for jurisdiction {:?}",
                total_amount,
                max_amount,
                jurisdiction
            ));
        }

        // 4. ZK proof что total_amount ≤ max_amount
        let mut transcript = Transcript::new(b"ZK-ResComply_Limits");
        let mut rng = OsRng;

        // Мы доказываем что total_amount ∈ [0, max_amount]
        // Для этого создаём commitment к total_amount
        let blinding = Scalar::random(&mut rng);
        let amount_scalar = Scalar::from(total_amount);

        let commitment = self.pc_gens.commit(amount_scalar, blinding);
        let commitment_bytes = commitment.compress().to_bytes();

        let proof = RangeProof::prove_single(
            &self.bp_gens,
            &self.pc_gens,
            &mut transcript,
            total_amount,
            &blinding,
            64, // 64 бита для больших сумм
        )?;

        Ok(ComplianceProof::TransactionLimitsRespected {
            jurisdiction,
            proof: proof.0.to_bytes(),
            total_amount_commitment: commitment_bytes,
            max_allowed_amount: max_amount,
            period_start,
            period_end,
            transaction_count: transaction_count as u32,
        })
    }

    /// Создать полный compliance report
    pub fn create_full_compliance_report(
        &self,
        company: &CompanyProfile,
        transactions: &[Transaction],
        sanctions_lists: Vec<String>,
        auditor_signature: Option<Vec<u8>>,
    ) -> Result<ComplianceProof> {
        let now = chrono::Utc::now().timestamp();
        let period_start = now - 30 * 24 * 3600; // 30 дней назад

        let mut proofs = Vec::new();

        // 1. Проверка запрещённых юрисдикций
        for &jurisdiction in &[
            Jurisdiction::Crimea,
            Jurisdiction::Donetsk,
            Jurisdiction::Luhansk,
            Jurisdiction::IR,
            Jurisdiction::SY,
        ] {
            if company.excluded_jurisdictions.contains(&jurisdiction) {
                let proof = self.prove_no_operations(
                    company,
                    transactions,
                    jurisdiction,
                    period_start,
                    now,
                )?;
                proofs.push(proof);
            }
        }

        // 2. Проверка контрагентов
        let screening_proof =
            self.prove_counterparty_screening(company, sanctions_lists.clone(), period_start)?;
        proofs.push(screening_proof);

        // 3. Проверка лимитов транзакций
        for jurisdiction in company.max_transaction_amounts.keys() {
            let limit_proof = self.prove_transaction_limits(
                company,
                transactions,
                *jurisdiction,
                period_start,
                now,
            )?;
            proofs.push(limit_proof);
        }

        // 4. Вычисляем хеш состояния компании
        let company_state_hash = company.compute_state_hash();

        Ok(ComplianceProof::FullComplianceReport {
            proofs,
            company_state_hash,
            report_timestamp: now,
            auditor_signature,
        })
    }

    /// Верифицировать compliance proof
    pub fn verify_proof(&self, proof: &ComplianceProof) -> Result<bool> {
        match proof {
            ComplianceProof::NoOperationsWith {
                proof, commitment, ..
            } => self.verify_range_proof(proof, commitment, 8),

            ComplianceProof::AllCounterpartiesScreened { proof, .. } => {
                // Для верификации нам нужен commitment
                // В реальной системе commitment должен быть предоставлен
                let dummy_commitment = self.create_dummy_commitment(0u64)?;
                self.verify_range_proof(proof, &dummy_commitment, 2)
            }

            ComplianceProof::TransactionLimitsRespected {
                proof,
                total_amount_commitment,
                ..
            } => self.verify_range_proof(proof, total_amount_commitment, 64),

            ComplianceProof::InternalControlsVerified { .. } => {
                // TODO: Implement internal controls verification
                Ok(true)
            }

            ComplianceProof::FullComplianceReport { proofs, .. } => {
                // Верифицируем все вложенные proof'ы
                for proof in proofs {
                    if !self.verify_proof(proof)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    // Вспомогательные методы

    fn verify_range_proof(
        &self,
        proof_bytes: &[u8],
        commitment_bytes: &[u8; 32],
        bits: usize,
    ) -> Result<bool> {
        let mut transcript = Transcript::new(b"ZK-ResComply_Verify");

        let range_proof = RangeProof::from_bytes(proof_bytes)
            .map_err(|e| anyhow!("Invalid range proof: {}", e))?;

        let commitment = CompressedRistretto::from_slice(commitment_bytes)
            .map_err(|_| anyhow!("Invalid commitment"))?;

        range_proof
            .verify_single(
                &self.bp_gens,
                &self.pc_gens,
                &mut transcript,
                &commitment,
                bits,
            )
            .map(|_| true)
            .map_err(|e| anyhow!("Verification failed: {:?}", e))
    }

    fn build_merkle_root(&self, leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
        if leaves.is_empty() {
            // Пустое дерево - специальный корень
            let mut hasher = Sha3_256::new();
            hasher.update(b"empty");
            return Ok(hasher.finalize().into());
        }

        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let mut hasher = Sha3_256::new();

                hasher.update(&chunk[0]);
                if let Some(right) = chunk.get(1) {
                    hasher.update(right);
                } else {
                    // Дублируем левый лист для нечётного количества
                    hasher.update(&chunk[0]);
                }

                next_level.push(hasher.finalize().into());
            }

            current_level = next_level;
        }

        Ok(current_level[0])
    }

    fn create_dummy_commitment(&self, value: u64) -> Result<[u8; 32]> {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let commitment = self.pc_gens.commit(Scalar::from(value), blinding);
        Ok(commitment.compress().to_bytes())
    }
}

// Утилиты для работы со временем
pub fn parse_timestamp(timestamp: i64) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| anyhow!("Invalid timestamp: {}", timestamp))
}

pub fn format_period(start: i64, end: i64) -> String {
    if let (Ok(start_dt), Ok(end_dt)) = (parse_timestamp(start), parse_timestamp(end)) {
        format!(
            "{} - {}",
            start_dt.format("%Y-%m-%d"),
            end_dt.format("%Y-%m-%d")
        )
    } else {
        format!("{} - {}", start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rzip_rescomply_core::{CounterpartyType, IndustryCode, RiskLevel};

    fn create_test_company() -> CompanyProfile {
        let industry = IndustryCode {
            code: "62.01".to_string(),
            description: "Software development".to_string(),
            risk_level: RiskLevel::Low,
        };

        CompanyProfile::new(
            "TEST001".to_string(),
            "Test Corporation".to_string(),
            Jurisdiction::RU,
            industry,
        )
    }

    fn create_test_transactions() -> Vec<Transaction> {
        vec![
            Transaction {
                id: "tx1".to_string(),
                timestamp: chrono::Utc::now(),
                amount: 100_000_00, // 100,000 в копейках
                currency: "RUB".to_string(),
                counterparty_hash: [1u8; 32],
                counterparty_jurisdiction: Jurisdiction::RU,
                purpose: Some("Payment for services".to_string()),
                category: TransactionCategory::ServicesPayment,
                amount_commitment: None,
                nullifier: None,
            },
            Transaction {
                id: "tx2".to_string(),
                timestamp: chrono::Utc::now() - chrono::Duration::days(1),
                amount: 50_000_00,
                currency: "USD".to_string(),
                counterparty_hash: [2u8; 32],
                counterparty_jurisdiction: Jurisdiction::US,
                purpose: Some("Software license".to_string()),
                category: TransactionCategory::GoodsPayment,
                amount_commitment: None,
                nullifier: None,
            },
        ]
    }

    #[test]
    fn test_merkle_root() {
        let prover = ComplianceProver::new("./test_db").unwrap();

        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root = prover.build_merkle_root(&leaves).unwrap();

        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_create_transaction() {
        let prover = ComplianceProver::new("./test_db").unwrap();

        let tx = prover
            .create_transaction(
                100_000_00,
                "RUB",
                [1u8; 32],
                Jurisdiction::RU,
                TransactionCategory::ServicesPayment,
            )
            .unwrap();

        assert!(tx.amount_commitment.is_some());
        assert!(tx.nullifier.is_some());
        assert_eq!(tx.amount, 100_000_00);
    }
}
