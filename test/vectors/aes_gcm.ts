// test/vectors/aes_gcm.ts
//
// AES-GCM mode test vectors.
//
// Sources:
//   McGrew & Viega — "The Galois/Counter Mode of Operation (GCM)"
//   January 2004 submission to NIST. The original NIST URL
//   (csrc.nist.gov/CryptoToolkit/modes/proposedmodes/gcm/gcm-spec.pdf)
//   no longer resolves; the 2004-11-05 Wayback Machine snapshot is
//   pinned in research-docs/specs/gcm-spec.pdf.
//   Sections covered: Appendix B (test cases 1–18) — all 18 cases below.
//
//   NIST SP 800-38D — Galois/Counter Mode (GCM) and GMAC (November 2007)
//   @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
//   Used as the normative reference for IV-length and tag-length rules
//   the McGrew-Viega test cases exercise.
//
// All hex strings are lowercase, no separators.
// Empty fields are encoded as the empty string ''.
//
// All 18 cases from gcm-spec.pdf Appendix B are present below. The
// distribution across key sizes is:
//   AES-128 — Test Cases 1–6
//   AES-192 — Test Cases 7–12
//   AES-256 — Test Cases 13–18
// Within each key size, the six cases cover empty/non-empty plaintext
// and AAD, and 96-bit / 64-bit / 480-bit IV variants (the 96-bit cases
// take the IV-prepending fast path; the others trigger GHASH-on-IV).
// All tags are 128-bit (32 hex characters, the maximum permitted by
// SP 800-38D §5.2.1.2).
//
// Phase-4 GCM tests use these 18 cases for the gate plus the AESAVS
// GCMVS .rsp corpora alongside this file (aes_gcmEncryptExtIV{128,192,256}.rsp
// and aes_gcmDecrypt{128,192,256}.rsp) for breadth.
//
// Audit status: VERIFIED — every byte transcribed directly from the
//   gcm-spec.pdf PDF (Wayback-archived McGrew-Viega submission), no
//   value derived from any GCM implementation.

// ============================================================
// Interfaces
// ============================================================

/**
 * A positive AES-GCM test vector: a (key, iv, aad, pt) input that
 * authenticated-encrypts to (ct, tag) under AES-GCM. Empty fields are
 * encoded as ''.
 */
export interface GcmVector {
	description: string;
	key:         string;  // hex (32, 48, or 64 chars = 128/192/256-bit)
	iv:          string;  // hex; any length permitted by SP 800-38D §5.2.1.1
	                      // (96-bit / 24-char IV is the recommended case)
	aad:         string;  // hex; may be empty
	pt:          string;  // hex; may be empty
	ct:          string;  // hex; same length as pt
	tag:         string;  // hex; typically 32 chars (16 bytes); GCM allows
	                      // shorter (4–16 byte) tags
}

/**
 * A negative AES-GCM test vector: a (key, iv, aad, ct, tag) input whose
 * authentication MUST fail under AES-GCM. There is no `pt` field —
 * decryption must throw an authentication error and never produce
 * plaintext. Tests use this shape to verify that decryption of tampered
 * input rejects rather than returning corrupted data.
 */
export interface GcmFailVector {
	description: string;
	key:         string;  // hex
	iv:          string;  // hex
	aad:         string;  // hex
	ct:          string;  // hex (the tampered ciphertext)
	tag:         string;  // hex (the tag the ciphertext claims to have)
}

// ============================================================
// Positive vectors — McGrew-Viega Appendix B Test Cases 1–18
// ============================================================

/**
 * The 18 worked AES-GCM test cases from the McGrew-Viega "GCM" paper,
 * Appendix B. Source: research-docs/specs/gcm-spec.pdf (2004-11-05
 * Wayback Machine snapshot of the original NIST URL). See file header.
 */
export const aesGcmVectors: GcmVector[] = [
	{
		description: 'McGrew-Viega Appendix B Test Case 1: AES-128, empty P, empty A, 96-bit IV',
		key: '00000000000000000000000000000000',
		iv: '000000000000000000000000',
		aad: '',
		pt: '',
		ct: '',
		tag: '58e2fccefa7e3061367f1d57a4e7455a',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 2: AES-128, 16-byte zero P, empty A, 96-bit IV',
		key: '00000000000000000000000000000000',
		iv: '000000000000000000000000',
		aad: '',
		pt: '00000000000000000000000000000000',
		ct: '0388dace60b6a392f328c2b971b2fe78',
		tag: 'ab6e47d42cec13bdf53a67b21257bddf',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 3: AES-128, 64-byte P, empty A, 96-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308',
		iv: 'cafebabefacedbaddecaf888',
		aad: '',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b391aafd255',
		ct:
			'42831ec2217774244b7221b784d0d49c' +
			'e3aa212f2c02a4e035c17e2329aca12e' +
			'21d514b25466931c7d8f6a5aac84aa05' +
			'1ba30b396a0aac973d58e091473f5985',
		tag: '4d5c2af327cd64a62cf35abd2ba6fab4',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 4: AES-128, 60-byte P with 20-byte A, 96-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308',
		iv: 'cafebabefacedbaddecaf888',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'42831ec2217774244b7221b784d0d49c' +
			'e3aa212f2c02a4e035c17e2329aca12e' +
			'21d514b25466931c7d8f6a5aac84aa05' +
			'1ba30b396a0aac973d58e091',
		tag: '5bc94fbc3221a5db94fae95ae7121a47',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 5: AES-128, 60-byte P, 20-byte A, 64-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308',
		iv: 'cafebabefacedbad',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'61353b4c2806934a777ff51fa22a4755' +
			'699b2a714fcdc6f83766e5f97b6c7423' +
			'73806900e49f24b22b097544d4896b42' +
			'4989b5e1ebac0f07c23f4598',
		tag: '3612d2e79e3b0785561be14aaca2fccb',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 6: AES-128, 60-byte P, 20-byte A, 480-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308',
		iv:
			'9313225df88406e555909c5aff5269aa' +
			'6a7a9538534f7da1e4c303d2a318a728' +
			'c3c0c95156809539fcf0e2429a6b5254' +
			'16aedbf5a0de6a57a637b39b',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'8ce24998625615b603a033aca13fb894' +
			'be9112a5c3a211a8ba262a3cca7e2ca7' +
			'01e4a9a4fba43c90ccdcb281d48c7c6f' +
			'd62875d2aca417034c34aee5',
		tag: '619cc5aefffe0bfa462af43c1699d050',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 7: AES-192, empty P, empty A, 96-bit IV',
		key: '000000000000000000000000000000000000000000000000',
		iv: '000000000000000000000000',
		aad: '',
		pt: '',
		ct: '',
		tag: 'cd33b28ac773f74ba00ed1f312572435',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 8: AES-192, 16-byte zero P, empty A, 96-bit IV',
		key: '000000000000000000000000000000000000000000000000',
		iv: '000000000000000000000000',
		aad: '',
		pt: '00000000000000000000000000000000',
		ct: '98e7247c07f0fe411c267e4384b0f600',
		tag: '2ff58d80033927ab8ef4d4587514f0fb',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 9: AES-192, 64-byte P, empty A, 96-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
		iv: 'cafebabefacedbaddecaf888',
		aad: '',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b391aafd255',
		ct:
			'3980ca0b3c00e841eb06fac4872a2757' +
			'859e1ceaa6efd984628593b40ca1e19c' +
			'7d773d00c144c525ac619d18c84a3f47' +
			'18e2448b2fe324d9ccda2710acade256',
		tag: '9924a7c8587336bfb118024db8674a14',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 10: AES-192, 60-byte P, 20-byte A, 96-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
		iv: 'cafebabefacedbaddecaf888',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'3980ca0b3c00e841eb06fac4872a2757' +
			'859e1ceaa6efd984628593b40ca1e19c' +
			'7d773d00c144c525ac619d18c84a3f47' +
			'18e2448b2fe324d9ccda2710',
		tag: '2519498e80f1478f37ba55bd6d27618c',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 11: AES-192, 60-byte P, 20-byte A, 64-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
		iv: 'cafebabefacedbad',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'0f10f599ae14a154ed24b36e25324db8' +
			'c566632ef2bbb34f8347280fc4507057' +
			'fddc29df9a471f75c66541d4d4dad1c9' +
			'e93a19a58e8b473fa0f062f7',
		tag: '65dcc57fcf623a24094fcca40d3533f8',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 12: AES-192, 60-byte P, 20-byte A, 480-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c',
		iv:
			'9313225df88406e555909c5aff5269aa' +
			'6a7a9538534f7da1e4c303d2a318a728' +
			'c3c0c95156809539fcf0e2429a6b5254' +
			'16aedbf5a0de6a57a637b39b',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'd27e88681ce3243c4830165a8fdcf9ff' +
			'1de9a1d8e6b447ef6ef7b79828666e45' +
			'81e79012af34ddd9e2f037589b292db3' +
			'e67c036745fa22e7e9b7373b',
		tag: 'dcf566ff291c25bbb8568fc3d376a6d9',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 13: AES-256, empty P, empty A, 96-bit IV',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		iv: '000000000000000000000000',
		aad: '',
		pt: '',
		ct: '',
		tag: '530f8afbc74536b9a963b4f1c4cb738b',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 14: AES-256, 16-byte zero P, empty A, 96-bit IV',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		iv: '000000000000000000000000',
		aad: '',
		pt: '00000000000000000000000000000000',
		ct: 'cea7403d4d606b6e074ec5d3baf39d18',
		tag: 'd0d1c8a799996bf0265b98b5d48ab919',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 15: AES-256, 64-byte P, empty A, 96-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
		iv: 'cafebabefacedbaddecaf888',
		aad: '',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b391aafd255',
		ct:
			'522dc1f099567d07f47f37a32a84427d' +
			'643a8cdcbfe5c0c97598a2bd2555d1aa' +
			'8cb08e48590dbb3da7b08b1056828838' +
			'c5f61e6393ba7a0abcc9f662898015ad',
		tag: 'b094dac5d93471bdec1a502270e3cc6c',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 16: AES-256, 60-byte P, 20-byte A, 96-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
		iv: 'cafebabefacedbaddecaf888',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'522dc1f099567d07f47f37a32a84427d' +
			'643a8cdcbfe5c0c97598a2bd2555d1aa' +
			'8cb08e48590dbb3da7b08b1056828838' +
			'c5f61e6393ba7a0abcc9f662',
		tag: '76fc6ece0f4e1768cddf8853bb2d551b',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 17: AES-256, 60-byte P, 20-byte A, 64-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
		iv: 'cafebabefacedbad',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'c3762df1ca787d32ae47c13bf19844cb' +
			'af1ae14d0b976afac52ff7d79bba9de0' +
			'feb582d33934a4f0954cc2363bc73f78' +
			'62ac430e64abe499f47c9b1f',
		tag: '3a337dbf46a792c45e454913fe2ea8f2',
	},
	{
		description: 'McGrew-Viega Appendix B Test Case 18: AES-256, 60-byte P, 20-byte A, 480-bit IV',
		key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
		iv:
			'9313225df88406e555909c5aff5269aa' +
			'6a7a9538534f7da1e4c303d2a318a728' +
			'c3c0c95156809539fcf0e2429a6b5254' +
			'16aedbf5a0de6a57a637b39b',
		aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
		pt:
			'd9313225f88406e5a55909c5aff5269a' +
			'86a7a9531534f7da2e4c303d8a318a72' +
			'1c3c0c95956809532fcf0e2449a6b525' +
			'b16aedf5aa0de657ba637b39',
		ct:
			'5a8def2f0c9e53f1f75d7853659e2a20' +
			'eeb2b22aafde6419a058ab4f6f746bf4' +
			'0fc0c3b780f244452da3ebf1c5d82cde' +
			'a2418997200ef82e44ae7e3f',
		tag: 'a44a8266ee1c8eb0c8b5d4cf5ae9f19a',
	},
];
