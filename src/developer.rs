use crate::engine::KernelEngine;
use crate::error::KernelXError;
use crate::origin::find_valid_nonce;
use crate::reconstruction::SettlementOutcome;
use crate::storage::MemoryStore;
use crate::state::VectorStateV1;
use crate::wallet::WalletContext;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulationReport {
    pub vectors: Vec<VectorStateV1>,
    pub records: usize,
}

pub struct SimulationHarness {
    pub engine: KernelEngine<MemoryStore>,
}

impl SimulationHarness {
    pub fn new() -> Self {
        Self {
            engine: KernelEngine::new(),
        }
    }

    pub fn wallet(&self) -> WalletContext {
        WalletContext::generate()
    }

    pub fn basic_flow(&mut self) -> Result<SimulationReport, KernelXError> {
        let wallet_a = WalletContext::generate();
        let wallet_b = WalletContext::generate();

        let seed_a = "seed-a";
        let seed_b = "seed-b";

        let nonce_a = find_valid_nonce(seed_a, 1, 1_000_000).ok_or(KernelXError::OriginRejected)?;
        let nonce_b = find_valid_nonce(seed_b, 1, 1_000_000).ok_or(KernelXError::OriginRejected)?;

        self.engine.origin_create(
            "v-a",
            wallet_a.public_key_hex(),
            "space-1",
            vec![1000, 2000],
            seed_a,
            nonce_a,
            1,
        )?;

        self.engine.origin_create(
            "v-b",
            wallet_b.public_key_hex(),
            "space-1",
            vec![50, 75],
            seed_b,
            nonce_b,
            1,
        )?;

        self.engine.transfer("v-a", "v-b", vec![250, 250])?;
        self.engine.drain("v-a", 100)?;
        self.engine.project("v-b", vec![10, 10], "escrow-1")?;
        self.engine.reconstruct(
            "v-b",
            SettlementOutcome {
                outcome_tag: "settled".to_string(),
                gains: vec![2, 1],
                losses: vec![0, 0],
            },
        )?;

        let vectors = self.engine.query_vectors()?;
        let records = self.engine.query_records()?.len();

        Ok(SimulationReport { vectors, records })
    }
}