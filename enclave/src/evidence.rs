// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

pub struct Evidence {
    pub profile: &'static str,
    pub attestation: Vec<u8>,
    pub pcr0: Option<String>,
    pub pcr8: Option<String>,
    pub measurements: BTreeMap<String, String>,
}

pub trait EvidenceProvider: Send + Sync {
    fn profile(&self) -> &'static str;

    fn attest(&self, public_key_spki_der: &[u8], nonce: &[u8]) -> Result<Evidence, String>;
}
