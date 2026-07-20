// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::evidence::{Evidence, EvidenceProvider};
use std::collections::BTreeMap;
use std::os::raw::{c_int, c_uchar, c_uint};
use std::ptr;
use std::sync::Mutex;

const QTSM_ATTESTATION_DOC_MAX_SIZE: usize = 64 * 1024;
const QTSM_PUBLIC_KEY_MAX_SIZE: usize = 1024;
const QTSM_NONCE_MAX_SIZE: usize = 512;

#[link(name = "qtsm")]
extern "C" {
    fn qtsm_lib_init() -> c_int;
    fn qtsm_lib_exit(qtsm_dev_fd: c_int);
    fn qtsm_get_attestation(
        fd: c_int,
        user_data: *const c_uchar,
        user_data_len: c_uint,
        nonce_data: *const c_uchar,
        nonce_data_len: c_uint,
        pubkey_data: *const c_uchar,
        pubkey_len: c_uint,
        att_doc_data: *mut c_uchar,
        att_doc_data_len: *mut c_uint,
    ) -> c_int;
}

pub struct QingTianEvidenceProvider {
    fd: c_int,
    lock: Mutex<()>,
}

impl QingTianEvidenceProvider {
    pub fn new() -> Result<Self, String> {
        let fd = unsafe { qtsm_lib_init() };
        if fd < 0 {
            return Err(format!("qtsm_lib_init failed: {fd}"));
        }
        Ok(Self {
            fd,
            lock: Mutex::new(()),
        })
    }
}

impl Drop for QingTianEvidenceProvider {
    fn drop(&mut self) {
        unsafe { qtsm_lib_exit(self.fd) };
    }
}

impl EvidenceProvider for QingTianEvidenceProvider {
    fn profile(&self) -> &'static str {
        "qingtian"
    }

    fn attest(&self, public_key_spki_der: &[u8], nonce: &[u8]) -> Result<Evidence, String> {
        if public_key_spki_der.len() > QTSM_PUBLIC_KEY_MAX_SIZE {
            return Err(format!(
                "qtsm public_key too large: {} > {QTSM_PUBLIC_KEY_MAX_SIZE}",
                public_key_spki_der.len()
            ));
        }
        if nonce.len() > QTSM_NONCE_MAX_SIZE {
            return Err(format!(
                "qtsm nonce too large: {} > {QTSM_NONCE_MAX_SIZE}",
                nonce.len()
            ));
        }

        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut attestation = vec![0u8; QTSM_ATTESTATION_DOC_MAX_SIZE];
        let mut attestation_len = attestation.len() as c_uint;
        let rc = unsafe {
            qtsm_get_attestation(
                self.fd,
                ptr::null(),
                0,
                nonce.as_ptr(),
                nonce.len() as c_uint,
                public_key_spki_der.as_ptr(),
                public_key_spki_der.len() as c_uint,
                attestation.as_mut_ptr(),
                &mut attestation_len,
            )
        };
        if rc != 0 {
            return Err(format!("qtsm_get_attestation failed: {rc}"));
        }
        let actual_len = attestation_len as usize;
        if actual_len == 0 || actual_len > attestation.len() {
            return Err(format!(
                "qtsm_get_attestation returned invalid length: {actual_len} (capacity {})",
                attestation.len()
            ));
        }
        attestation.truncate(actual_len);

        Ok(Evidence {
            profile: self.profile(),
            attestation,
            pcr0: None,
            pcr8: None,
            measurements: BTreeMap::new(),
        })
    }
}
