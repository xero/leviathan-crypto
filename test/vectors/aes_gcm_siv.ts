// test/vectors/aes_gcm_siv.ts
//
// AES-GCM-SIV (RFC 8452) test vectors.
//
// Sources:
//   RFC 8452, Gueron, Langley, Lindell, "AES-GCM-SIV: Nonce
//   Misuse-Resistant Authenticated Encryption", April 2019.
//   @see https://www.rfc-editor.org/rfc/rfc8452.txt
//   Section covered: Appendix C (Test Vectors). Subsections:
//     C.1  AEAD_AES_128_GCM_SIV  , 24 vectors
//     C.2  AEAD_AES_256_GCM_SIV  , 24 vectors
//     C.3  Counter Wrap Tests    ,  2 vectors (AES-256-GCM-SIV)
//   Total: 50 vectors.
//
// All hex strings are lowercase, no separators.
// Empty fields are encoded as the empty string ''.
//
// These are POSITIVE vectors only: every record encrypts (key, nonce,
// aad, plaintext) -> result via AES-GCM-SIV. FAIL/tamper vectors for
// the open direction (single-byte tag flip, single-byte CT flip, AAD
// tamper, IV tamper, key tamper) are synthesised at unit-test time
// in Phase 4b-impl. The corpus does not need to ship them.
//
// The 13 hex/string fields per record carry the full RFC-published
// trace for each vector, not just (key, nonce, aad, pt, ct, tag).
// The intermediates (recordAuthKey, recordEncKey, polyvalInput,
// polyvalResult, polyvalXorNonce, polyvalMasked, tag,
// initialCounter) let unit tests bisect a failure to the offending
// sub-step (key derivation, POLYVAL hashing, tag formation, or CTR
// encryption) rather than testing only the final `result`.
//
// Audit status: VERIFIED, every byte transcribed directly from
//   RFC 8452 text, then byte-equality-cross-checked by an independent
//   Rust implementation (`aes-gcm-siv` crate, RustCrypto) via
//   `scripts/verify-vectors`.

// ============================================================
// Interfaces
// ============================================================

/**
 * One AES-GCM-SIV test vector per RFC 8452 Appendix C. Every field
 * after `nonce` is a derived intermediate captured verbatim from
 * the RFC's published trace; they let unit tests bisect a failure
 * to the offending sub-step (key derivation, POLYVAL hashing, tag
 * formation, or CTR encryption) rather than testing only the final
 * `result`.
 *
 * Field semantics:
 *   - `recordAuthKey`   is `message_authentication_key` from RFC §4.
 *   - `recordEncKey`    is `message_encryption_key` from RFC §4.
 *   - `polyvalInput`    is `padded_ad ++ padded_plaintext ++ length_block`.
 *   - `polyvalResult`   is `S_s = POLYVAL(record_auth_key, polyvalInput)`.
 *   - `polyvalXorNonce` is `polyvalResult` with bytes [0..12] XORed
 *                         against `nonce` (bytes [12..16] unchanged).
 *   - `polyvalMasked`   is `polyvalXorNonce` with the high bit of
 *                         byte 15 cleared (bitmask 0x7f on byte 15).
 *   - `tag`             is `AES_ENC(recordEncKey, polyvalMasked)`.
 *   - `initialCounter`  is `tag` with the high bit of byte 15 set
 *                         (bitmask 0x80 ORed into byte 15).
 *   - `result`          is `AES_CTR(recordEncKey, initialCounter,
 *                         plaintext) ++ tag`. Length =
 *                         `plaintext.length + 16`.
 */
export interface AesGcmSivVector {
	description:     string;
	plaintext:       string;  // hex; may be empty
	aad:             string;  // hex; may be empty
	key:             string;  // hex, 32 (AES-128) or 64 (AES-256) chars
	nonce:           string;  // hex, 24 chars (12 bytes, always)
	recordAuthKey:   string;  // hex, 32 chars
	recordEncKey:    string;  // hex, 32 (AES-128) or 64 (AES-256) chars
	polyvalInput:    string;  // hex
	polyvalResult:   string;  // hex, 32 chars
	polyvalXorNonce: string;  // hex, 32 chars
	polyvalMasked:   string;  // hex, 32 chars
	tag:             string;  // hex, 32 chars
	initialCounter:  string;  // hex, 32 chars
	result:          string;  // hex; length = (plaintext bytes + 16) * 2
}

// ============================================================
// C.1, AEAD_AES_128_GCM_SIV (24 vectors)
// ============================================================

export const aesGcmSiv128Vectors: AesGcmSivVector[] = [
	{
		description: 'RFC 8452 Appendix C.1 #1: AES-128-GCM-SIV, PT 0 B, AAD 0 B',
		plaintext: '',
		aad: '',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput: '00000000000000000000000000000000',
		polyvalResult: '00000000000000000000000000000000',
		polyvalXorNonce: '03000000000000000000000000000000',
		polyvalMasked: '03000000000000000000000000000000',
		tag: 'dc20e2d83f25705bb49e439eca56de25',
		initialCounter: 'dc20e2d83f25705bb49e439eca56dea5',
		result: 'dc20e2d83f25705bb49e439eca56de25',
	},
	{
		description: 'RFC 8452 Appendix C.1 #2: AES-128-GCM-SIV, PT 8 B, AAD 0 B',
		plaintext: '0100000000000000',
		aad: '',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput: '0100000000000000000000000000000000000000000000004000000000000000',
		polyvalResult: 'eb93b7740962c5e49d2a90a7dc5cec74',
		polyvalXorNonce: 'e893b7740962c5e49d2a90a7dc5cec74',
		polyvalMasked: 'e893b7740962c5e49d2a90a7dc5cec74',
		tag: '578782fff6013b815b287c22493a364c',
		initialCounter: '578782fff6013b815b287c22493a36cc',
		result: 'b5d839330ac7b786578782fff6013b815b287c22493a364c',
	},
	{
		description: 'RFC 8452 Appendix C.1 #3: AES-128-GCM-SIV, PT 12 B, AAD 0 B',
		plaintext: '010000000000000000000000',
		aad: '',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput: '0100000000000000000000000000000000000000000000006000000000000000',
		polyvalResult: '48eb6c6c5a2dbe4a1dde508fee06361b',
		polyvalXorNonce: '4beb6c6c5a2dbe4a1dde508fee06361b',
		polyvalMasked: '4beb6c6c5a2dbe4a1dde508fee06361b',
		tag: 'a4978db357391a0bc4fdec8b0d106639',
		initialCounter: 'a4978db357391a0bc4fdec8b0d1066b9',
		result: '7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639',
	},
	{
		description: 'RFC 8452 Appendix C.1 #4: AES-128-GCM-SIV, PT 16 B, AAD 0 B',
		plaintext: '01000000000000000000000000000000',
		aad: '',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput: '0100000000000000000000000000000000000000000000008000000000000000',
		polyvalResult: '20806c26e3c1de019e111255708031d6',
		polyvalXorNonce: '23806c26e3c1de019e111255708031d6',
		polyvalMasked: '23806c26e3c1de019e11125570803156',
		tag: '303aaf90f6fe21199c6068577437a0c4',
		initialCounter: '303aaf90f6fe21199c6068577437a0c4',
		result: '743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4',
	},
	{
		description: 'RFC 8452 Appendix C.1 #5: AES-128-GCM-SIV, PT 32 B, AAD 0 B',
		plaintext: '0100000000000000000000000000000002000000000000000000000000000000',
		aad: '',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'00000000000000000001000000000000',
		polyvalResult: 'ce6edc9a50b36d9a98986bbf6a261c3b',
		polyvalXorNonce: 'cd6edc9a50b36d9a98986bbf6a261c3b',
		polyvalMasked: 'cd6edc9a50b36d9a98986bbf6a261c3b',
		tag: '1a8e45dcd4578c667cd86847bf6155ff',
		initialCounter: '1a8e45dcd4578c667cd86847bf6155ff',
		result:
			'84e07e62ba83a6585417245d7ec413a9' +
			'fe427d6315c09b57ce45f2e3936a9445' +
			'1a8e45dcd4578c667cd86847bf6155ff',
	},
	{
		description: 'RFC 8452 Appendix C.1 #6: AES-128-GCM-SIV, PT 48 B, AAD 0 B',
		plaintext:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000',
		aad: '',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'00000000000000008001000000000000',
		polyvalResult: '81388746bc22d26b2abc3dcb15754222',
		polyvalXorNonce: '82388746bc22d26b2abc3dcb15754222',
		polyvalMasked: '82388746bc22d26b2abc3dcb15754222',
		tag: '5e6e311dbf395d35b0fe39c2714388f8',
		initialCounter: '5e6e311dbf395d35b0fe39c2714388f8',
		result:
			'3fd24ce1f5a67b75bf2351f181a475c7' +
			'b800a5b4d3dcf70106b1eea82fa1d64d' +
			'f42bf7226122fa92e17a40eeaac1201b' +
			'5e6e311dbf395d35b0fe39c2714388f8',
	},
	{
		description: 'RFC 8452 Appendix C.1 #7: AES-128-GCM-SIV, PT 64 B, AAD 0 B',
		plaintext:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000',
		aad: '',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'00000000000000000002000000000000',
		polyvalResult: '1e39b6d3344d348f6044f89935d1cf78',
		polyvalXorNonce: '1d39b6d3344d348f6044f89935d1cf78',
		polyvalMasked: '1d39b6d3344d348f6044f89935d1cf78',
		tag: '8a263dd317aa88d56bdf3936dba75bb8',
		initialCounter: '8a263dd317aa88d56bdf3936dba75bb8',
		result:
			'2433668f1058190f6d43e360f4f35cd8' +
			'e475127cfca7028ea8ab5c20f7ab2af0' +
			'2516a2bdcbc08d521be37ff28c152bba' +
			'36697f25b4cd169c6590d1dd39566d3f' +
			'8a263dd317aa88d56bdf3936dba75bb8',
	},
	{
		description: 'RFC 8452 Appendix C.1 #8: AES-128-GCM-SIV, PT 8 B, AAD 1 B',
		plaintext: '0200000000000000',
		aad: '01',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'08000000000000004000000000000000',
		polyvalResult: 'b26781e7e2c1376f96bec195f3709b2a',
		polyvalXorNonce: 'b16781e7e2c1376f96bec195f3709b2a',
		polyvalMasked: 'b16781e7e2c1376f96bec195f3709b2a',
		tag: '3b0a1a2560969cdf790d99759abd1508',
		initialCounter: '3b0a1a2560969cdf790d99759abd1588',
		result: '1e6daba35669f4273b0a1a2560969cdf790d99759abd1508',
	},
	{
		description: 'RFC 8452 Appendix C.1 #9: AES-128-GCM-SIV, PT 12 B, AAD 1 B',
		plaintext: '020000000000000000000000',
		aad: '01',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'08000000000000006000000000000000',
		polyvalResult: '111f5affb18e4cc1164a01bdc12a4145',
		polyvalXorNonce: '121f5affb18e4cc1164a01bdc12a4145',
		polyvalMasked: '121f5affb18e4cc1164a01bdc12a4145',
		tag: '08299c5102745aaa3a0c469fad9e075a',
		initialCounter: '08299c5102745aaa3a0c469fad9e07da',
		result: '296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a',
	},
	{
		description: 'RFC 8452 Appendix C.1 #10: AES-128-GCM-SIV, PT 16 B, AAD 1 B',
		plaintext: '02000000000000000000000000000000',
		aad: '01',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'08000000000000008000000000000000',
		polyvalResult: '79745ab508622c8a958543675fac4688',
		polyvalXorNonce: '7a745ab508622c8a958543675fac4688',
		polyvalMasked: '7a745ab508622c8a958543675fac4608',
		tag: '8f8936ec039e4e4bb97ebd8c4457441f',
		initialCounter: '8f8936ec039e4e4bb97ebd8c4457449f',
		result: 'e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f',
	},
	{
		description: 'RFC 8452 Appendix C.1 #11: AES-128-GCM-SIV, PT 32 B, AAD 1 B',
		plaintext: '0200000000000000000000000000000003000000000000000000000000000000',
		aad: '01',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'08000000000000000001000000000000',
		polyvalResult: '2ce7daaf7c89490822051255b12eca6b',
		polyvalXorNonce: '2fe7daaf7c89490822051255b12eca6b',
		polyvalMasked: '2fe7daaf7c89490822051255b12eca6b',
		tag: 'e6af6a7f87287da059a71684ed3498e1',
		initialCounter: 'e6af6a7f87287da059a71684ed3498e1',
		result:
			'620048ef3c1e73e57e02bb8562c416a3' +
			'19e73e4caac8e96a1ecb2933145a1d71' +
			'e6af6a7f87287da059a71684ed3498e1',
	},
	{
		description: 'RFC 8452 Appendix C.1 #12: AES-128-GCM-SIV, PT 48 B, AAD 1 B',
		plaintext:
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000',
		aad: '01',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'08000000000000008001000000000000',
		polyvalResult: '9ca987715d69c1786711dfcd22f830fc',
		polyvalXorNonce: '9fa987715d69c1786711dfcd22f830fc',
		polyvalMasked: '9fa987715d69c1786711dfcd22f8307c',
		tag: '6a8cc3865f76897c2e4b245cf31c51f2',
		initialCounter: '6a8cc3865f76897c2e4b245cf31c51f2',
		result:
			'50c8303ea93925d64090d07bd109dfd9' +
			'515a5a33431019c17d93465999a8b005' +
			'3201d723120a8562b838cdff25bf9d1e' +
			'6a8cc3865f76897c2e4b245cf31c51f2',
	},
	{
		description: 'RFC 8452 Appendix C.1 #13: AES-128-GCM-SIV, PT 64 B, AAD 1 B',
		plaintext:
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'05000000000000000000000000000000',
		aad: '01',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'05000000000000000000000000000000' +
			'08000000000000000002000000000000',
		polyvalResult: 'ffcd05d5770f34ad9267f0a59994b15a',
		polyvalXorNonce: 'fccd05d5770f34ad9267f0a59994b15a',
		polyvalMasked: 'fccd05d5770f34ad9267f0a59994b15a',
		tag: 'cdc46ae475563de037001ef84ae21744',
		initialCounter: 'cdc46ae475563de037001ef84ae217c4',
		result:
			'2f5c64059db55ee0fb847ed513003746' +
			'aca4e61c711b5de2e7a77ffd02da42fe' +
			'ec601910d3467bb8b36ebbaebce5fba3' +
			'0d36c95f48a3e7980f0e7ac299332a80' +
			'cdc46ae475563de037001ef84ae21744',
	},
	{
		description: 'RFC 8452 Appendix C.1 #14: AES-128-GCM-SIV, PT 4 B, AAD 12 B',
		plaintext: '02000000',
		aad: '010000000000000000000000',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'60000000000000002000000000000000',
		polyvalResult: 'f6ce9d3dcd68a2fd603c7ecc18fb9918',
		polyvalXorNonce: 'f5ce9d3dcd68a2fd603c7ecc18fb9918',
		polyvalMasked: 'f5ce9d3dcd68a2fd603c7ecc18fb9918',
		tag: '07eb1f84fb28f8cb73de8e99e2f48a14',
		initialCounter: '07eb1f84fb28f8cb73de8e99e2f48a94',
		result: 'a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14',
	},
	{
		description: 'RFC 8452 Appendix C.1 #15: AES-128-GCM-SIV, PT 20 B, AAD 18 B',
		plaintext: '0300000000000000000000000000000004000000',
		aad: '010000000000000000000000000000000200',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'9000000000000000a000000000000000',
		polyvalResult: '4781d492cb8f926c504caa36f61008fe',
		polyvalXorNonce: '4481d492cb8f926c504caa36f61008fe',
		polyvalMasked: '4481d492cb8f926c504caa36f610087e',
		tag: '24afc9805e976f451e6d87f6fe106514',
		initialCounter: '24afc9805e976f451e6d87f6fe106594',
		result:
			'6bb0fecf5ded9b77f902c7d5da236a43' +
			'91dd029724afc9805e976f451e6d87f6' +
			'fe106514',
	},
	{
		description: 'RFC 8452 Appendix C.1 #16: AES-128-GCM-SIV, PT 18 B, AAD 20 B',
		plaintext: '030000000000000000000000000000000400',
		aad: '0100000000000000000000000000000002000000',
		key: '01000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'd9b360279694941ac5dbc6987ada7377',
		recordEncKey: '4004a0dcd862f2a57360219d2d44ef6c',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'a0000000000000009000000000000000',
		polyvalResult: '75cbc23a1a10e348aeb8e384b5cc79fd',
		polyvalXorNonce: '76cbc23a1a10e348aeb8e384b5cc79fd',
		polyvalMasked: '76cbc23a1a10e348aeb8e384b5cc797d',
		tag: 'bff9b2ef00fb47920cc72a0c0f13b9fd',
		initialCounter: 'bff9b2ef00fb47920cc72a0c0f13b9fd',
		result:
			'44d0aaf6fb2f1f34add5e8064e83e12a' +
			'2adabff9b2ef00fb47920cc72a0c0f13' +
			'b9fd',
	},
	{
		description: 'RFC 8452 Appendix C.1 #17: AES-128-GCM-SIV, PT 0 B, AAD 0 B (random key/nonce)',
		plaintext: '',
		aad: '',
		key: 'e66021d5eb8e4f4066d4adb9c33560e4',
		nonce: 'f46e44bb3da0015c94f70887',
		recordAuthKey: '036ee1fe2d7926af68898095e54e7b3c',
		recordEncKey: '5e46482396008223b5c1d25173d87539',
		polyvalInput: '00000000000000000000000000000000',
		polyvalResult: '00000000000000000000000000000000',
		polyvalXorNonce: 'f46e44bb3da0015c94f7088700000000',
		polyvalMasked: 'f46e44bb3da0015c94f7088700000000',
		tag: 'a4194b79071b01a87d65f706e3949578',
		initialCounter: 'a4194b79071b01a87d65f706e39495f8',
		result: 'a4194b79071b01a87d65f706e3949578',
	},
	{
		description: 'RFC 8452 Appendix C.1 #18: AES-128-GCM-SIV, PT 3 B, AAD 5 B (random key/nonce)',
		plaintext: '7a806c',
		aad: '46bb91c3c5',
		key: '36864200e0eaf5284d884a0e77d31646',
		nonce: 'bae8e37fc83441b16034566b',
		recordAuthKey: '3e28de1120b2981a0155795ca2812af6',
		recordEncKey: '6d4b78b31a4c9c03d8db0f42f7507fae',
		polyvalInput:
			'46bb91c3c50000000000000000000000' +
			'7a806c00000000000000000000000000' +
			'28000000000000001800000000000000',
		polyvalResult: '43d9a745511dcfa21b96dd606f1d5720',
		polyvalXorNonce: 'f931443a99298e137ba28b0b6f1d5720',
		polyvalMasked: 'f931443a99298e137ba28b0b6f1d5720',
		tag: '711bd85bc1e4d3e0a462e074eea428a8',
		initialCounter: '711bd85bc1e4d3e0a462e074eea428a8',
		result: 'af60eb711bd85bc1e4d3e0a462e074eea428a8',
	},
	{
		description: 'RFC 8452 Appendix C.1 #19: AES-128-GCM-SIV, PT 6 B, AAD 10 B (random key/nonce)',
		plaintext: 'bdc66f146545',
		aad: 'fc880c94a95198874296',
		key: 'aedb64a6c590bc84d1a5e269e4b47801',
		nonce: 'afc0577e34699b9e671fdd4f',
		recordAuthKey: '43b8de9cea62330d15cccfc84a33e8c8',
		recordEncKey: '8e54631607e431e095b54852868e3a27',
		polyvalInput:
			'fc880c94a95198874296000000000000' +
			'bdc66f14654500000000000000000000' +
			'50000000000000003000000000000000',
		polyvalResult: '26498e0d2b1ef004e808c458e8f2f515',
		polyvalXorNonce: '8989d9731f776b9a8f171917e8f2f515',
		polyvalMasked: '8989d9731f776b9a8f171917e8f2f515',
		tag: 'd6a9c45545cfc11f03ad743dba20f966',
		initialCounter: 'd6a9c45545cfc11f03ad743dba20f9e6',
		result: 'bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966',
	},
	{
		description: 'RFC 8452 Appendix C.1 #20: AES-128-GCM-SIV, PT 9 B, AAD 15 B (random key/nonce)',
		plaintext: '1177441f195495860f',
		aad: '046787f3ea22c127aaf195d1894728',
		key: 'd5cc1fd161320b6920ce07787f86743b',
		nonce: '275d1ab32f6d1f0434d8848c',
		recordAuthKey: '8a51df64d93eaf667c2c09bd454ce5c5',
		recordEncKey: '43ab276c2b4a473918ca73f2dd85109c',
		polyvalInput:
			'046787f3ea22c127aaf195d189472800' +
			'1177441f195495860f00000000000000' +
			'78000000000000004800000000000000',
		polyvalResult: '63a3451c0b23345ad02bba59956517cf',
		polyvalXorNonce: '44fe5faf244e2b5ee4f33ed5956517cf',
		polyvalMasked: '44fe5faf244e2b5ee4f33ed59565174f',
		tag: '1d02fd0cd174c84fc5dae2f60f52fd2b',
		initialCounter: '1d02fd0cd174c84fc5dae2f60f52fdab',
		result: '4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b',
	},
	{
		description: 'RFC 8452 Appendix C.1 #21: AES-128-GCM-SIV, PT 12 B, AAD 20 B (random key/nonce)',
		plaintext: '9f572c614b4745914474e7c7',
		aad: 'c9882e5386fd9f92ec489c8fde2be2cf97e74e93',
		key: 'b3fed1473c528b8426a582995929a149',
		nonce: '9e9ad8780c8d63d0ab4149c0',
		recordAuthKey: '22f50707a95dd416df069d670cb775e8',
		recordEncKey: 'f674a5584ee21fe97b4cebc468ab61e4',
		polyvalInput:
			'c9882e5386fd9f92ec489c8fde2be2cf' +
			'97e74e93000000000000000000000000' +
			'9f572c614b4745914474e7c700000000' +
			'a0000000000000006000000000000000',
		polyvalResult: '0cca0423fba9d77fe7e2e6963b08cdd0',
		polyvalXorNonce: '9250dc5bf724b4af4ca3af563b08cdd0',
		polyvalMasked: '9250dc5bf724b4af4ca3af563b08cd50',
		tag: 'c1dc2f871fb7561da1286e655e24b7b0',
		initialCounter: 'c1dc2f871fb7561da1286e655e24b7b0',
		result: 'f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0',
	},
	{
		description: 'RFC 8452 Appendix C.1 #22: AES-128-GCM-SIV, PT 15 B, AAD 25 B (random key/nonce)',
		plaintext: '0d8c8451178082355c9e940fea2f58',
		aad: '2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a',
		key: '2d4ed87da44102952ef94b02b805249b',
		nonce: 'ac80e6f61455bfac8308a2d4',
		recordAuthKey: '0b00a29a83e7e95b92e3a0783b29f140',
		recordEncKey: 'a430c27f285aed913005975c42eed5f3',
		polyvalInput:
			'2950a70d5a1db2316fd568378da107b5' +
			'2b0da55210cc1c1b0a00000000000000' +
			'0d8c8451178082355c9e940fea2f5800' +
			'c8000000000000007800000000000000',
		polyvalResult: '1086ef25247aa41009bbc40871d9b350',
		polyvalXorNonce: 'bc0609d3302f1bbc8ab366dc71d9b350',
		polyvalMasked: 'bc0609d3302f1bbc8ab366dc71d9b350',
		tag: '83b3449b9f39552de99dc214a1190b0b',
		initialCounter: '83b3449b9f39552de99dc214a1190b8b',
		result: 'c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b',
	},
	{
		description: 'RFC 8452 Appendix C.1 #23: AES-128-GCM-SIV, PT 18 B, AAD 30 B (random key/nonce)',
		plaintext: '6b3db4da3d57aa94842b9803a96e07fb6de7',
		aad: '1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f',
		key: 'bde3b2f204d1e9f8b06bc47f9745b3d1',
		nonce: 'ae06556fb6aa7890bebc18fe',
		recordAuthKey: '21c874a8bad3603d1c3e8784df5b3f9f',
		recordEncKey: 'd1c16d72651c3df504eae27129d818e8',
		polyvalInput:
			'1860f762ebfbd08284e421702de0de18' +
			'baa9c9596291b08466f37de21c7f0000' +
			'6b3db4da3d57aa94842b9803a96e07fb' +
			'6de70000000000000000000000000000' +
			'f0000000000000009000000000000000',
		polyvalResult: '55462a5afa0da8d646481e049ef9c764',
		polyvalXorNonce: 'fb407f354ca7d046f8f406fa9ef9c764',
		polyvalMasked: 'fb407f354ca7d046f8f406fa9ef9c764',
		tag: '3e377094f04709f64d7b985310a4db84',
		initialCounter: '3e377094f04709f64d7b985310a4db84',
		result:
			'6298b296e24e8cc35dce0bed484b7f30' +
			'd5803e377094f04709f64d7b985310a4' +
			'db84',
	},
	{
		description: 'RFC 8452 Appendix C.1 #24: AES-128-GCM-SIV, PT 21 B, AAD 35 B (random key/nonce)',
		plaintext: 'e42a3c02c25b64869e146d7b233987bddfc240871d',
		aad:
			'7576f7028ec6eb5ea7e298342a94d4b2' +
			'02b370ef9768ec6561c4fe6b7e7296fa' +
			'859c21',
		key: 'f901cfe8a69615a93fdf7a98cad48179',
		nonce: '6245709fb18853f68d833640',
		recordAuthKey: '3724f55f1d22ac0ab830da0b6a995d74',
		recordEncKey: '75ac87b70c05db287de779006105a344',
		polyvalInput:
			'7576f7028ec6eb5ea7e298342a94d4b2' +
			'02b370ef9768ec6561c4fe6b7e7296fa' +
			'859c2100000000000000000000000000' +
			'e42a3c02c25b64869e146d7b233987bd' +
			'dfc240871d0000000000000000000000' +
			'1801000000000000a800000000000000',
		polyvalResult: '4cbba090f03f7d1188ea55749fa6c7bd',
		polyvalXorNonce: '2efed00f41b72ee7056963349fa6c7bd',
		polyvalMasked: '2efed00f41b72ee7056963349fa6c73d',
		tag: '2d15506c84a9edd65e13e9d24a2a6e70',
		initialCounter: '2d15506c84a9edd65e13e9d24a2a6ef0',
		result:
			'391cc328d484a4f46406181bcd62efd9' +
			'b3ee197d052d15506c84a9edd65e13e9' +
			'd24a2a6e70',
	},
];

// ============================================================
// C.2, AEAD_AES_256_GCM_SIV (24 vectors)
// ============================================================

export const aesGcmSiv256Vectors: AesGcmSivVector[] = [
	{
		description: 'RFC 8452 Appendix C.2 #1: AES-256-GCM-SIV, PT 0 B, AAD 0 B',
		plaintext: '',
		aad: '',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput: '00000000000000000000000000000000',
		polyvalResult: '00000000000000000000000000000000',
		polyvalXorNonce: '03000000000000000000000000000000',
		polyvalMasked: '03000000000000000000000000000000',
		tag: '07f5f4169bbf55a8400cd47ea6fd400f',
		initialCounter: '07f5f4169bbf55a8400cd47ea6fd408f',
		result: '07f5f4169bbf55a8400cd47ea6fd400f',
	},
	{
		description: 'RFC 8452 Appendix C.2 #2: AES-256-GCM-SIV, PT 8 B, AAD 0 B',
		plaintext: '0100000000000000',
		aad: '',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput: '0100000000000000000000000000000000000000000000004000000000000000',
		polyvalResult: '05230f62f0eac8aa14fe4d646b59cd41',
		polyvalXorNonce: '06230f62f0eac8aa14fe4d646b59cd41',
		polyvalMasked: '06230f62f0eac8aa14fe4d646b59cd41',
		tag: '843122130f7364b761e0b97427e3df28',
		initialCounter: '843122130f7364b761e0b97427e3dfa8',
		result: 'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28',
	},
	{
		description: 'RFC 8452 Appendix C.2 #3: AES-256-GCM-SIV, PT 12 B, AAD 0 B',
		plaintext: '010000000000000000000000',
		aad: '',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput: '0100000000000000000000000000000000000000000000006000000000000000',
		polyvalResult: '6d81a24732fd6d03ae5af544720a1c13',
		polyvalXorNonce: '6e81a24732fd6d03ae5af544720a1c13',
		polyvalMasked: '6e81a24732fd6d03ae5af544720a1c13',
		tag: '8ca50da9ae6559e48fd10f6e5c9ca17e',
		initialCounter: '8ca50da9ae6559e48fd10f6e5c9ca1fe',
		result: '9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e',
	},
	{
		description: 'RFC 8452 Appendix C.2 #4: AES-256-GCM-SIV, PT 16 B, AAD 0 B',
		plaintext: '01000000000000000000000000000000',
		aad: '',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput: '0100000000000000000000000000000000000000000000008000000000000000',
		polyvalResult: '74eee2bf7c9a165f8b25dea73db32a6d',
		polyvalXorNonce: '77eee2bf7c9a165f8b25dea73db32a6d',
		polyvalMasked: '77eee2bf7c9a165f8b25dea73db32a6d',
		tag: 'c9eac6fa700942702e90862383c6c366',
		initialCounter: 'c9eac6fa700942702e90862383c6c3e6',
		result: '85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366',
	},
	{
		description: 'RFC 8452 Appendix C.2 #5: AES-256-GCM-SIV, PT 32 B, AAD 0 B',
		plaintext: '0100000000000000000000000000000002000000000000000000000000000000',
		aad: '',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'00000000000000000001000000000000',
		polyvalResult: '899b6381b3d46f0def7aa0517ba188f5',
		polyvalXorNonce: '8a9b6381b3d46f0def7aa0517ba188f5',
		polyvalMasked: '8a9b6381b3d46f0def7aa0517ba18875',
		tag: 'e819e63abcd020b006a976397632eb5d',
		initialCounter: 'e819e63abcd020b006a976397632ebdd',
		result:
			'4a6a9db4c8c6549201b9edb53006cba8' +
			'21ec9cf850948a7c86c68ac7539d027f' +
			'e819e63abcd020b006a976397632eb5d',
	},
	{
		description: 'RFC 8452 Appendix C.2 #6: AES-256-GCM-SIV, PT 48 B, AAD 0 B',
		plaintext:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000',
		aad: '',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'00000000000000008001000000000000',
		polyvalResult: 'c1f8593d8fc29b0c290cae1992f71f51',
		polyvalXorNonce: 'c2f8593d8fc29b0c290cae1992f71f51',
		polyvalMasked: 'c2f8593d8fc29b0c290cae1992f71f51',
		tag: '790bc96880a99ba804bd12c0e6a22cc4',
		initialCounter: '790bc96880a99ba804bd12c0e6a22cc4',
		result:
			'c00d121893a9fa603f48ccc1ca3c57ce' +
			'7499245ea0046db16c53c7c66fe717e3' +
			'9cf6c748837b61f6ee3adcee17534ed5' +
			'790bc96880a99ba804bd12c0e6a22cc4',
	},
	{
		description: 'RFC 8452 Appendix C.2 #7: AES-256-GCM-SIV, PT 64 B, AAD 0 B',
		plaintext:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000',
		aad: '',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'00000000000000000002000000000000',
		polyvalResult: '6ef38b06046c7c0e225efaef8e2ec4c4',
		polyvalXorNonce: '6df38b06046c7c0e225efaef8e2ec4c4',
		polyvalMasked: '6df38b06046c7c0e225efaef8e2ec444',
		tag: '112864c269fc0d9d88c61fa47e39aa08',
		initialCounter: '112864c269fc0d9d88c61fa47e39aa88',
		result:
			'c2d5160a1f8683834910acdafc41fbb1' +
			'632d4a353e8b905ec9a5499ac34f96c7' +
			'e1049eb080883891a4db8caaa1f99dd0' +
			'04d80487540735234e3744512c6f90ce' +
			'112864c269fc0d9d88c61fa47e39aa08',
	},
	{
		description: 'RFC 8452 Appendix C.2 #8: AES-256-GCM-SIV, PT 8 B, AAD 1 B',
		plaintext: '0200000000000000',
		aad: '01',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'08000000000000004000000000000000',
		polyvalResult: '34e57bafe011b9b36fc6821b7ffb3354',
		polyvalXorNonce: '37e57bafe011b9b36fc6821b7ffb3354',
		polyvalMasked: '37e57bafe011b9b36fc6821b7ffb3354',
		tag: '91213f267e3b452f02d01ae33e4ec854',
		initialCounter: '91213f267e3b452f02d01ae33e4ec8d4',
		result: '1de22967237a813291213f267e3b452f02d01ae33e4ec854',
	},
	{
		description: 'RFC 8452 Appendix C.2 #9: AES-256-GCM-SIV, PT 12 B, AAD 1 B',
		plaintext: '020000000000000000000000',
		aad: '01',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'08000000000000006000000000000000',
		polyvalResult: '5c47d68a22061c1ad5623a3b66a8e206',
		polyvalXorNonce: '5f47d68a22061c1ad5623a3b66a8e206',
		polyvalMasked: '5f47d68a22061c1ad5623a3b66a8e206',
		tag: 'c1a4a19ae800941ccdc57cc8413c277f',
		initialCounter: 'c1a4a19ae800941ccdc57cc8413c27ff',
		result: '163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f',
	},
	{
		description: 'RFC 8452 Appendix C.2 #10: AES-256-GCM-SIV, PT 16 B, AAD 1 B',
		plaintext: '02000000000000000000000000000000',
		aad: '01',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'08000000000000008000000000000000',
		polyvalResult: '452896726c616746f01d11d82911d478',
		polyvalXorNonce: '462896726c616746f01d11d82911d478',
		polyvalMasked: '462896726c616746f01d11d82911d478',
		tag: 'b292d28ff61189e8e49f3875ef91aff7',
		initialCounter: 'b292d28ff61189e8e49f3875ef91aff7',
		result: 'c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7',
	},
	{
		description: 'RFC 8452 Appendix C.2 #11: AES-256-GCM-SIV, PT 32 B, AAD 1 B',
		plaintext: '0200000000000000000000000000000003000000000000000000000000000000',
		aad: '01',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'08000000000000000001000000000000',
		polyvalResult: '4e58c1e341c9bb0ae34eda9509dfc90c',
		polyvalXorNonce: '4d58c1e341c9bb0ae34eda9509dfc90c',
		polyvalMasked: '4d58c1e341c9bb0ae34eda9509dfc90c',
		tag: 'aea1bad12702e1965604374aab96dbbc',
		initialCounter: 'aea1bad12702e1965604374aab96dbbc',
		result:
			'07dad364bfc2b9da89116d7bef6daaaf' +
			'6f255510aa654f920ac81b94e8bad365' +
			'aea1bad12702e1965604374aab96dbbc',
	},
	{
		description: 'RFC 8452 Appendix C.2 #12: AES-256-GCM-SIV, PT 48 B, AAD 1 B',
		plaintext:
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000',
		aad: '01',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'08000000000000008001000000000000',
		polyvalResult: '2566a4aff9a525df9772c16d4eaf8d2a',
		polyvalXorNonce: '2666a4aff9a525df9772c16d4eaf8d2a',
		polyvalMasked: '2666a4aff9a525df9772c16d4eaf8d2a',
		tag: '03332742b228c647173616cfd44c54eb',
		initialCounter: '03332742b228c647173616cfd44c54eb',
		result:
			'c67a1f0f567a5198aa1fcc8e3f213143' +
			'36f7f51ca8b1af61feac35a86416fa47' +
			'fbca3b5f749cdf564527f2314f42fe25' +
			'03332742b228c647173616cfd44c54eb',
	},
	{
		description: 'RFC 8452 Appendix C.2 #13: AES-256-GCM-SIV, PT 64 B, AAD 1 B',
		plaintext:
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'05000000000000000000000000000000',
		aad: '01',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'05000000000000000000000000000000' +
			'08000000000000000002000000000000',
		polyvalResult: 'da58d2f61b0a9d343b2f37fb0c519733',
		polyvalXorNonce: 'd958d2f61b0a9d343b2f37fb0c519733',
		polyvalMasked: 'd958d2f61b0a9d343b2f37fb0c519733',
		tag: '5bde0285037c5de81e5b570a049b62a0',
		initialCounter: '5bde0285037c5de81e5b570a049b62a0',
		result:
			'67fd45e126bfb9a79930c43aad2d3696' +
			'7d3f0e4d217c1e551f59727870beefc9' +
			'8cb933a8fce9de887b1e40799988db1f' +
			'c3f91880ed405b2dd298318858467c89' +
			'5bde0285037c5de81e5b570a049b62a0',
	},
	{
		description: 'RFC 8452 Appendix C.2 #14: AES-256-GCM-SIV, PT 4 B, AAD 12 B',
		plaintext: '02000000',
		aad: '010000000000000000000000',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'60000000000000002000000000000000',
		polyvalResult: '6dc76ae84b88916e073a303aafde05cf',
		polyvalXorNonce: '6ec76ae84b88916e073a303aafde05cf',
		polyvalMasked: '6ec76ae84b88916e073a303aafde054f',
		tag: '1835e517741dfddccfa07fa4661b74cf',
		initialCounter: '1835e517741dfddccfa07fa4661b74cf',
		result: '22b3f4cd1835e517741dfddccfa07fa4661b74cf',
	},
	{
		description: 'RFC 8452 Appendix C.2 #15: AES-256-GCM-SIV, PT 20 B, AAD 18 B',
		plaintext: '0300000000000000000000000000000004000000',
		aad: '010000000000000000000000000000000200',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'9000000000000000a000000000000000',
		polyvalResult: '973ef4fd04bd31d193816ab26f8655ca',
		polyvalXorNonce: '943ef4fd04bd31d193816ab26f8655ca',
		polyvalMasked: '943ef4fd04bd31d193816ab26f86554a',
		tag: 'b879ad976d8242acc188ab59cabfe307',
		initialCounter: 'b879ad976d8242acc188ab59cabfe387',
		result:
			'43dd0163cdb48f9fe3212bf61b201976' +
			'067f342bb879ad976d8242acc188ab59' +
			'cabfe307',
	},
	{
		description: 'RFC 8452 Appendix C.2 #16: AES-256-GCM-SIV, PT 18 B, AAD 20 B',
		plaintext: '030000000000000000000000000000000400',
		aad: '0100000000000000000000000000000002000000',
		key: '0100000000000000000000000000000000000000000000000000000000000000',
		nonce: '030000000000000000000000',
		recordAuthKey: 'b5d3c529dfafac43136d2d11be284d7f',
		recordEncKey: 'b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222',
		polyvalInput:
			'01000000000000000000000000000000' +
			'02000000000000000000000000000000' +
			'03000000000000000000000000000000' +
			'04000000000000000000000000000000' +
			'a0000000000000009000000000000000',
		polyvalResult: '2cbb6b7ab2dbffefb797f825f826870c',
		polyvalXorNonce: '2fbb6b7ab2dbffefb797f825f826870c',
		polyvalMasked: '2fbb6b7ab2dbffefb797f825f826870c',
		tag: 'cfcdf5042112aa29685c912fc2056543',
		initialCounter: 'cfcdf5042112aa29685c912fc20565c3',
		result:
			'462401724b5ce6588d5a54aae5375513' +
			'a075cfcdf5042112aa29685c912fc205' +
			'6543',
	},
	{
		description: 'RFC 8452 Appendix C.2 #17: AES-256-GCM-SIV, PT 0 B, AAD 0 B (random key/nonce)',
		plaintext: '',
		aad: '',
		key: 'e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200',
		nonce: 'e0eaf5284d884a0e77d31646',
		recordAuthKey: 'e40d26f82774aa27f47b047b608b9585',
		recordEncKey: '7c7c3d9a542cef53dde0e6de9b5800400f82e73ec5f7ee41b7ba8dcb9ba078c3',
		polyvalInput: '00000000000000000000000000000000',
		polyvalResult: '00000000000000000000000000000000',
		polyvalXorNonce: 'e0eaf5284d884a0e77d3164600000000',
		polyvalMasked: 'e0eaf5284d884a0e77d3164600000000',
		tag: '169fbb2fbf389a995f6390af22228a62',
		initialCounter: '169fbb2fbf389a995f6390af22228ae2',
		result: '169fbb2fbf389a995f6390af22228a62',
	},
	{
		description: 'RFC 8452 Appendix C.2 #18: AES-256-GCM-SIV, PT 3 B, AAD 5 B (random key/nonce)',
		plaintext: '671fdd',
		aad: '4fbdc66f14',
		key: 'bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269',
		nonce: 'e4b47801afc0577e34699b9e',
		recordAuthKey: 'b546f5a850d0a90adfe39e95c2510fc6',
		recordEncKey: 'b9d1e239d62cbb5c49273ddac8838bdcc53bca478a770f07087caa4e0a924a55',
		polyvalInput:
			'4fbdc66f140000000000000000000000' +
			'671fdd00000000000000000000000000' +
			'28000000000000001800000000000000',
		polyvalResult: 'b91f91f96b159a7c611c05035b839e92',
		polyvalXorNonce: '5dabe9f8c4d5cd0255759e9d5b839e92',
		polyvalMasked: '5dabe9f8c4d5cd0255759e9d5b839e12',
		tag: '93da9bb81333aee0c785b240d319719d',
		initialCounter: '93da9bb81333aee0c785b240d319719d',
		result: '0eaccb93da9bb81333aee0c785b240d319719d',
	},
	{
		description: 'RFC 8452 Appendix C.2 #19: AES-256-GCM-SIV, PT 6 B, AAD 10 B (random key/nonce)',
		plaintext: '195495860f04',
		aad: '6787f3ea22c127aaf195',
		key: '6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3',
		nonce: '2f6d1f0434d8848c1177441f',
		recordAuthKey: 'e156e1f9b0b07b780cbe30f259e3c8da',
		recordEncKey: '6fc1c494519f944aae52fcd8b14e5b171b5a9429d3b76e430d49940c0021d612',
		polyvalInput:
			'6787f3ea22c127aaf195000000000000' +
			'195495860f0400000000000000000000' +
			'50000000000000003000000000000000',
		polyvalResult: '2c480ed9d236b1df24c6eec109bd40c1',
		polyvalXorNonce: '032511dde6ee355335b1aade09bd40c1',
		polyvalMasked: '032511dde6ee355335b1aade09bd4041',
		tag: '6b62b84dc40c84636a5ec12020ec8c2c',
		initialCounter: '6b62b84dc40c84636a5ec12020ec8cac',
		result: 'a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c',
	},
	{
		description: 'RFC 8452 Appendix C.2 #20: AES-256-GCM-SIV, PT 9 B, AAD 15 B (random key/nonce)',
		plaintext: 'c9882e5386fd9f92ec',
		aad: '489c8fde2be2cf97e74e932d4ed87d',
		key: 'd1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0',
		nonce: '9f572c614b4745914474e7c7',
		recordAuthKey: '0533fd71f4119257361a3ff1469dd4e5',
		recordEncKey: '4feba89799be8ac3684fa2bb30ade0ea51390e6d87dcf3627d2ee44493853abe',
		polyvalInput:
			'489c8fde2be2cf97e74e932d4ed87d00' +
			'c9882e5386fd9f92ec00000000000000' +
			'78000000000000004800000000000000',
		polyvalResult: 'bf160bc9ded8c63057d2c38aae552fb4',
		polyvalXorNonce: '204127a8959f83a113a6244dae552fb4',
		polyvalMasked: '204127a8959f83a113a6244dae552f34',
		tag: 'c0fd3dc6628dfe55ebb0b9fb2295c8c2',
		initialCounter: 'c0fd3dc6628dfe55ebb0b9fb2295c8c2',
		result: '0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2',
	},
	{
		description: 'RFC 8452 Appendix C.2 #21: AES-256-GCM-SIV, PT 12 B, AAD 20 B (random key/nonce)',
		plaintext: '1db2316fd568378da107b52b',
		aad: '0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f',
		key: 'a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235',
		nonce: '5c9e940fea2f582950a70d5a',
		recordAuthKey: '64779ab10ee8a280272f14cc8851b727',
		recordEncKey: '25f40fc63f49d3b9016a8eeeb75846e0d72ca36ddbd312b6f5ef38ad14bd2651',
		polyvalInput:
			'0da55210cc1c1b0abde3b2f204d1e9f8' +
			'b06bc47f000000000000000000000000' +
			'1db2316fd568378da107b52b00000000' +
			'a0000000000000006000000000000000',
		polyvalResult: 'cc86ee22c861e1fd474c84676b42739c',
		polyvalXorNonce: '90187a2d224eb9d417eb893d6b42739c',
		polyvalMasked: '90187a2d224eb9d417eb893d6b42731c',
		tag: '404099c2587f64979f21826706d497d5',
		initialCounter: '404099c2587f64979f21826706d497d5',
		result: '8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5',
	},
	{
		description: 'RFC 8452 Appendix C.2 #22: AES-256-GCM-SIV, PT 15 B, AAD 25 B (random key/nonce)',
		plaintext: '21702de0de18baa9c9596291b08466',
		aad: 'f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f',
		key: '9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb',
		nonce: '6de71860f762ebfbd08284e4',
		recordAuthKey: '27c2959ed4daea3b1f52e849478de376',
		recordEncKey: '307a38a5a6cf231c0a9af3b527f23a62e9a6ff09aff8ae669f760153e864fc93',
		polyvalInput:
			'f37de21c7ff901cfe8a69615a93fdf7a' +
			'98cad481796245709f00000000000000' +
			'21702de0de18baa9c9596291b0846600' +
			'c8000000000000007800000000000000',
		polyvalResult: 'c4fa5e5b713853703bcf8e6424505fa5',
		polyvalXorNonce: 'a91d463b865ab88beb4d0a8024505fa5',
		polyvalMasked: 'a91d463b865ab88beb4d0a8024505f25',
		tag: 'b3080d28f6ebb5d3648ce97bd5ba67fd',
		initialCounter: 'b3080d28f6ebb5d3648ce97bd5ba67fd',
		result: '793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd',
	},
	{
		description: 'RFC 8452 Appendix C.2 #23: AES-256-GCM-SIV, PT 18 B, AAD 30 B (random key/nonce)',
		plaintext: 'b202b370ef9768ec6561c4fe6b7e7296fa85',
		aad: '9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7',
		key: 'b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7',
		nonce: '028ec6eb5ea7e298342a94d4',
		recordAuthKey: '670b98154076ddb59b7a9137d0dcc0f0',
		recordEncKey: '78116d78507fbe69d4a820c350f55c7cb36c3c9287df0e9614b142b76a587c3f',
		polyvalInput:
			'9c2159058b1f0fe91433a5bdc20e214e' +
			'ab7fecef4454a10ef0657df21ac70000' +
			'b202b370ef9768ec6561c4fe6b7e7296' +
			'fa850000000000000000000000000000' +
			'f0000000000000009000000000000000',
		polyvalResult: '4e4108f09f41d797dc9256f8da8d58c7',
		polyvalXorNonce: '4ccfce1bc1e6350fe8b8c22cda8d58c7',
		polyvalMasked: '4ccfce1bc1e6350fe8b8c22cda8d5847',
		tag: '454fc2a154fea91f8363a39fec7d0a49',
		initialCounter: '454fc2a154fea91f8363a39fec7d0ac9',
		result:
			'857e16a64915a787637687db4a951963' +
			'5cdd454fc2a154fea91f8363a39fec7d' +
			'0a49',
	},
	{
		description: 'RFC 8452 Appendix C.2 #24: AES-256-GCM-SIV, PT 21 B, AAD 35 B (random key/nonce)',
		plaintext: 'ced532ce4159b035277d4dfbb7db62968b13cd4eec',
		aad:
			'734320ccc9d9bbbb19cb81b2af4ecbc3' +
			'e72834321f7aa0f70b7282b4f33df23f' +
			'167541',
		key: '3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23',
		nonce: '688089e55540db1872504e1c',
		recordAuthKey: 'cb8c3aa3f8dbaeb4b28a3e86ff6625f8',
		recordEncKey: '02426ce1aa3ab31313b0848469a1b5fc6c9af9602600b195b04ad407026bc06d',
		polyvalInput:
			'734320ccc9d9bbbb19cb81b2af4ecbc3' +
			'e72834321f7aa0f70b7282b4f33df23f' +
			'16754100000000000000000000000000' +
			'ced532ce4159b035277d4dfbb7db6296' +
			'8b13cd4eec0000000000000000000000' +
			'1801000000000000a800000000000000',
		polyvalResult: 'ffd503c7dd712eb3791b7114b17bb0cf',
		polyvalXorNonce: '97558a228831f5ab0b4b3f08b17bb0cf',
		polyvalMasked: '97558a228831f5ab0b4b3f08b17bb04f',
		tag: '9d6c7029675b89eaf4ba1ded1a286594',
		initialCounter: '9d6c7029675b89eaf4ba1ded1a286594',
		result:
			'626660c26ea6612fb17ad91e8e767639' +
			'edd6c9faee9d6c7029675b89eaf4ba1d' +
			'ed1a286594',
	},
];

// ============================================================
// C.3, Counter Wrap Tests (2 vectors, AES-256-GCM-SIV)
// ============================================================

// The tests in this section use AEAD_AES_256_GCM_SIV and are
// crafted to test correct wrapping of the block counter
// (RFC 8452 §C.3 prose).

export const aesGcmSivCounterWrapVectors: AesGcmSivVector[] = [
	{
		description: 'RFC 8452 Appendix C.3 #1: AES-256-GCM-SIV, counter wrap (PT 32 B, AAD 0 B)',
		plaintext: '000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108',
		aad: '',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		nonce: '000000000000000000000000',
		recordAuthKey: 'dc95c078a24089895275f3d86b4fb868',
		recordEncKey: '779b38d15bffb63d39d6e9ae76a9b2f375d11b0e3a68c422845c7d4690fa594f',
		polyvalInput:
			'00000000000000000000000000000000' +
			'4db923dc793ee6497c76dcc03a98e108' +
			'00000000000000000001000000000000',
		polyvalResult: '7367cdb411b730128dd56e8edc0eff56',
		polyvalXorNonce: '7367cdb411b730128dd56e8edc0eff56',
		polyvalMasked: '7367cdb411b730128dd56e8edc0eff56',
		tag: 'ffffffff000000000000000000000000',
		initialCounter: 'ffffffff000000000000000000000080',
		result:
			'f3f80f2cf0cb2dd9c5984fcda908456c' +
			'c537703b5ba70324a6793a7bf218d3ea' +
			'ffffffff000000000000000000000000',
	},
	{
		description: 'RFC 8452 Appendix C.3 #2: AES-256-GCM-SIV, counter wrap (PT 24 B, AAD 0 B)',
		plaintext: 'eb3640277c7ffd1303c7a542d02d3e4c0000000000000000',
		aad: '',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		nonce: '000000000000000000000000',
		recordAuthKey: 'dc95c078a24089895275f3d86b4fb868',
		recordEncKey: '779b38d15bffb63d39d6e9ae76a9b2f375d11b0e3a68c422845c7d4690fa594f',
		polyvalInput:
			'eb3640277c7ffd1303c7a542d02d3e4c' +
			'00000000000000000000000000000000' +
			'0000000000000000c000000000000000',
		polyvalResult: '7367cdb411b730128dd56e8edc0eff56',
		polyvalXorNonce: '7367cdb411b730128dd56e8edc0eff56',
		polyvalMasked: '7367cdb411b730128dd56e8edc0eff56',
		tag: 'ffffffff000000000000000000000000',
		initialCounter: 'ffffffff000000000000000000000080',
		result:
			'18ce4f0b8cb4d0cac65fea8f79257b20' +
			'888e53e72299e56dffffffff00000000' +
			'0000000000000000',
	},
];
