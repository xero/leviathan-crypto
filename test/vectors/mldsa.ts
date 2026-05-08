// test/vectors/mldsa.ts
//
// NIST ACVP ML-DSA test vectors (FIPS 204) — barrel re-export.
//
// Sources:
//   ACVP-Server/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json
//   ACVP-Server/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json
//   ACVP-Server/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json
//
// All three corpora share vsId=42. HashML-DSA vectors are merged into
// the sigGen / sigVer corpora via the per-record `preHash` discriminator.
//
// Audit status: VERIFIED (NIST official ACVP — never modify values).

export type {
	KeyGenVector as MlDsaKeyGenVector,
} from './mldsa_keygen.js';

export {
	ml_dsa_44_keygen,
	ml_dsa_65_keygen,
	ml_dsa_87_keygen,
} from './mldsa_keygen.js';

export type {
	SigGenVector as MlDsaSigGenVector,
} from './mldsa_siggen.js';

export {
	ml_dsa_44_siggen,
	ml_dsa_65_siggen,
	ml_dsa_87_siggen,
} from './mldsa_siggen.js';

export type {
	SigVerVector as MlDsaSigVerVector,
} from './mldsa_sigver.js';

export {
	ml_dsa_44_sigver,
	ml_dsa_65_sigver,
	ml_dsa_87_sigver,
} from './mldsa_sigver.js';
