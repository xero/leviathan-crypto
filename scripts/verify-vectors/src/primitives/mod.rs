// Hand-rolled cryptographic primitives that aren't available in the
// RustCrypto crates we already depend on. Each module documents what it
// implements and against which spec.

pub mod hchacha20;
pub mod cbc;
pub mod pkcs7;
