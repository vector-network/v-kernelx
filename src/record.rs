use crate::state::{now_ms, CertificationState, VectorStateV1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationKind {
    OriginCreate,
    Transfer,
    Drain,
    Project,
    Reconstruct,
    Certify,
    Query,
    Custom(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorRecordV1 {
    pub schema: String,
    pub record_id: String,
    pub vector_id: String,
    pub before: Option<VectorStateV1>,
    pub after: VectorStateV1,
    pub operation: OperationKind,
    pub parameters: Value,
    pub certification: CertificationState,
    pub timestamp_ms: u64,
    pub proof: String,
}

fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    write_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    fn encode(value: &Value, buf: &mut Vec<u8>) {
        match value {
            Value::Null => write_u8(buf, 0),
            Value::Bool(b) => {
                write_u8(buf, 1);
                write_u8(buf, if *b { 1 } else { 0 });
            }
            Value::Number(n) => {
                write_u8(buf, 2);
                write_str(buf, &n.to_string());
            }
            Value::String(s) => {
                write_u8(buf, 3);
                write_str(buf, s);
            }
            Value::Array(items) => {
                write_u8(buf, 4);
                write_u64(buf, items.len() as u64);
                for item in items {
                    encode(item, buf);
                }
            }
            Value::Object(map) => {
                write_u8(buf, 5);
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                write_u64(buf, keys.len() as u64);
                for key in keys {
                    write_str(buf, key);
                    if let Some(v) = map.get(key) {
                        encode(v, buf);
                    } else {
                        write_u8(buf, 0);
                    }
                }
            }
        }
    }

    let mut buf = Vec::new();
    encode(value, &mut buf);
    buf
}

fn canonical_record_bytes(record: &VectorRecordV1) -> Vec<u8> {
    let mut buf = Vec::new();
    write_str(&mut buf, &record.schema);
    write_str(&mut buf, &record.record_id);
    write_str(&mut buf, &record.vector_id);
    write_u8(&mut buf, if record.before.is_some() { 1 } else { 0 });
    if let Some(before) = &record.before {
        let bytes = serde_json::to_vec(before).unwrap_or_default();
        write_u64(&mut buf, bytes.len() as u64);
        buf.extend_from_slice(&bytes);
    }
    let after_bytes = serde_json::to_vec(&record.after).unwrap_or_default();
    write_u64(&mut buf, after_bytes.len() as u64);
    buf.extend_from_slice(&after_bytes);

    let op_tag = match &record.operation {
        OperationKind::OriginCreate => "ORIGIN_CREATE",
        OperationKind::Transfer => "TRANSFER",
        OperationKind::Drain => "DRAIN",
        OperationKind::Project => "PROJECT",
        OperationKind::Reconstruct => "RECONSTRUCT",
        OperationKind::Certify => "CERTIFY",
        OperationKind::Query => "QUERY",
        OperationKind::Custom(name) => name.as_str(),
    };
    write_str(&mut buf, op_tag);

    let params = canonical_json_bytes(&record.parameters);
    write_u64(&mut buf, params.len() as u64);
    buf.extend_from_slice(&params);

    let cert_bytes = serde_json::to_vec(&record.certification).unwrap_or_default();
    write_u64(&mut buf, cert_bytes.len() as u64);
    buf.extend_from_slice(&cert_bytes);

    write_u64(&mut buf, record.timestamp_ms);
    buf
}

impl VectorRecordV1 {
    pub fn new(
        record_id: impl Into<String>,
        vector_id: impl Into<String>,
        before: Option<VectorStateV1>,
        after: VectorStateV1,
        operation: OperationKind,
        parameters: Value,
    ) -> Self {
        let certification = after.certification.clone();
        let timestamp_ms = now_ms();
        let mut record = Self {
            schema: "v.kernelx/VectorRecordV1".to_string(),
            record_id: record_id.into(),
            vector_id: vector_id.into(),
            before,
            after,
            operation,
            parameters,
            certification,
            timestamp_ms,
            proof: String::new(),
        };
        record.proof = record.hash();
        record
    }

    pub fn hash(&self) -> String {
        let bytes = canonical_record_bytes(self);

        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&bytes);
        let _sha256_digest = sha256_hasher.finalize();

        let digest = blake3::hash(&bytes);
        digest.to_hex().to_string()
    }
}

pub fn make_record_id(prefix: &str, vector_id: &str, discriminator: impl AsRef<str>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix.as_bytes());
    hasher.update(b":");
    hasher.update(vector_id.as_bytes());
    hasher.update(b":");
    hasher.update(discriminator.as_ref().as_bytes());
    hasher.finalize().to_hex().to_string()
}