// ML-KEM (FIPS 203) ACVP test vectors — barrel re-export.
//
// ACVP source:
//   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/
//   ML-KEM-keyGen-FIPS203/internalProjection.json   (vsId=42, 75 AFT vectors)
//   ML-KEM-encapDecap-FIPS203/internalProjection.json (vsId=42, 165 vectors)
//
// Audit status: VERIFIED (NIST official — never modify values)

export type {
	KeyGenVector as KyberKeyGenVector,
} from './kyber_keygen.js';

export {
	ml_kem_512_keygen,
	ml_kem_768_keygen,
	ml_kem_1024_keygen,
} from './kyber_keygen.js';

export type {
	EncapVector  as KyberEncapVector,
	DecapValVector as KyberDecapVector,
	KeyCheckVector as KyberKeyCheckVector,
} from './kyber_encapdecap.js';

export {
	ml_kem_512_encap,
	ml_kem_768_encap,
	ml_kem_1024_encap,
	ml_kem_512_decap_val,
	ml_kem_768_decap_val,
	ml_kem_1024_decap_val,
	ml_kem_512_decap_key_check,
	ml_kem_512_encap_key_check,
	ml_kem_768_decap_key_check,
	ml_kem_768_encap_key_check,
	ml_kem_1024_decap_key_check,
	ml_kem_1024_encap_key_check,
} from './kyber_encapdecap.js';
