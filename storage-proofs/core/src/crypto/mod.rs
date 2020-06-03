use sha2::{Digest, Sha256};
pub mod aes;
pub mod feistel;
pub mod pedersen;
pub mod sloth;
pub mod xor;

pub fn derive_porep_domain_seed(domain_separation_tag: &str, porep_id: [u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain(domain_separation_tag)
        .chain(porep_id)
        .result()
        .into()
}
