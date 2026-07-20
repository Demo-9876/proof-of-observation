// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::evidence::{Evidence, EvidenceProvider};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::sync::Mutex;

pub struct NitroEvidenceProvider {
    fd: i32,
    lock: Mutex<()>,
}

impl NitroEvidenceProvider {
    pub fn new() -> Self {
        Self {
            fd: nsm_init(),
            lock: Mutex::new(()),
        }
    }
}

impl EvidenceProvider for NitroEvidenceProvider {
    fn profile(&self) -> &'static str {
        "nitro"
    }

    fn attest(&self, public_key_spki_der: &[u8], nonce: &[u8]) -> Result<Evidence, String> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        match nsm_process_request(
            self.fd,
            Request::Attestation {
                user_data: None,
                nonce: Some(ByteBuf::from(nonce.to_vec())),
                public_key: Some(ByteBuf::from(public_key_spki_der.to_vec())),
            },
        ) {
            Response::Attestation { document } => Ok(Evidence {
                profile: self.profile(),
                attestation: document,
                pcr0: None,
                pcr8: None,
                measurements: BTreeMap::new(),
            }),
            other => Err(format!("nsm: {:?}", other)),
        }
    }
}
