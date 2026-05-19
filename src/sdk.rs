use crate::engine::KernelEngine;
use crate::error::KernelXError;
use crate::reconstruction::SettlementOutcome;
use crate::state::VectorStateV1;
use crate::storage::MemoryStore;
use crate::wallet::WalletContext;

pub struct VectorKernel {
    pub engine: KernelEngine<MemoryStore>,
}

impl VectorKernel {
    pub fn new() -> Self {
        Self {
            engine: KernelEngine::new(),
        }
    }

    pub fn wallet(&self) -> WalletContext {
        WalletContext::generate()
    }

    pub fn origin_create(
        &mut self,
        vector_id: impl Into<String>,
        owner_pubkey: impl Into<String>,
        space_id: impl Into<String>,
        components: Vec<u128>,
        seed: impl Into<String>,
        nonce: u64,
        difficulty: u32,
    ) -> Result<VectorStateV1, KernelXError> {
        self.engine
            .origin_create(vector_id, owner_pubkey, space_id, components, seed, nonce, difficulty)
    }

    pub fn transfer(
        &mut self,
        from_id: &str,
        to_id: &str,
        amount: Vec<u128>,
    ) -> Result<(VectorStateV1, VectorStateV1), KernelXError> {
        self.engine.transfer(from_id, to_id, amount)
    }

    pub fn drain(&mut self, vector_id: &str, basis_points: u16) -> Result<VectorStateV1, KernelXError> {
        self.engine.drain(vector_id, basis_points)
    }

    pub fn project(
        &mut self,
        vector_id: &str,
        projected_components: Vec<u128>,
        escrow_id: impl Into<String>,
    ) -> Result<VectorStateV1, KernelXError> {
        self.engine.project(vector_id, projected_components, escrow_id)
    }

    pub fn reconstruct(
        &mut self,
        vector_id: &str,
        outcome: SettlementOutcome,
    ) -> Result<VectorStateV1, KernelXError> {
        self.engine.reconstruct(vector_id, outcome)
    }

    pub fn certify(&mut self, vector_id: &str) -> Result<VectorStateV1, KernelXError> {
        self.engine.certify(vector_id)
    }

    pub fn query(&self, vector_id: &str) -> Result<Option<VectorStateV1>, KernelXError> {
        self.engine.query_vector(vector_id)
    }

    pub fn query_vectors(&self) -> Result<Vec<VectorStateV1>, KernelXError> {
        self.engine.query_vectors()
    }

    pub fn query_records(&self) -> Result<Vec<crate::record::VectorRecordV1>, KernelXError> {
        self.engine.query_records()
    }

    pub fn replay_canonical_history(
        &self,
    ) -> Result<crate::replay::ReplayResult, KernelXError> {
        self.engine.replay_canonical_history()
    }

    pub fn current_state_root(&self) -> Result<crate::state::StateRoot, KernelXError> {
        self.engine.current_state_root()
    }
}