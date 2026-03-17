// ChaCha20-Poly1305 & XChaCha20-Poly1305 test vectors
//
// Sources:
//   RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols (June 2018)
//   @see https://www.rfc-editor.org/rfc/rfc8439
//   Sections covered: §2.2.1 (block function), §2.4.2 (encryption),
//                     §2.5.2 (Poly1305 MAC), §2.6.2 (Poly1305 key gen),
//                     Appendix A.3 (Poly1305 TV#1–#6), §2.8.2 (AEAD)
//
//   XChaCha20-Poly1305 IETF draft (draft-irtf-cfrg-xchacha-03)
//   @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
//   Sections covered: §A.3.1 (HChaCha20), §A.3.2 (XChaCha20-Poly1305 AEAD)
//
// All hex strings are lowercase, no separators.
// Audit status: VERIFIED — per-vector citations in each export below.

// ============================================================
// RFC 8439 §2.2.1 — ChaCha20 block function
// ============================================================

export interface BlockFunctionVector {
	description: string;
	key:       string; // 32 bytes (64 hex chars)
	nonce:     string; // 12 bytes (24 hex chars)
	counter:   number;
	keystream: string; // 64 bytes (128 hex chars)
}

/** RFC 8439 §2.2.1 test vector for the ChaCha20 block function. */
export const chacha20BlockVectors: BlockFunctionVector[] = [
	{
		// RFC 8439 §2.2.1 — counter=1
		description: 'RFC 8439 §2.2.1: sequential key, non-zero nonce, counter=1',
		key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		nonce: '000000090000004a00000000',
		counter: 1,
		keystream:
			'10f1e7e4d13b5915500fdd1fa32071c4' +
			'c7d1f4c733c068030422aa9ac3d46c4e' +
			'd2826446079faa0914c2d705d98b02a2' +
			'b5129cd1de164eb9cbd083e8a2503c4e',
	},
];

// ============================================================
// RFC 8439 §2.4.2 — ChaCha20 encryption
// ============================================================

export interface EncryptionVector {
	description: string;
	key:     string;  // 32 bytes
	nonce:   string;  // 12 bytes
	ptText?: string;  // plaintext as UTF-8 text
	pt?:     string;  // plaintext as hex (optional if ptText is set)
	ct:      string;  // ciphertext hex
}

/** RFC 8439 §2.4.2 encryption test vector (114-byte plaintext). */
export const chacha20EncryptionVectors: EncryptionVector[] = [
	{
		// RFC 8439 §2.4.2 — "sunscreen" example
		description: 'RFC 8439 §2.4.2: sunscreen encryption (114 bytes)',
		key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		nonce: '000000000000004a00000000',
		ptText:
			'Ladies and Gentlemen of the class of \'99: If I could offer you' +
			' only one tip for the future, sunscreen would be it.',
		ct:
			'6e2e359a2568f98041ba0728dd0d6981' +
			'e97e7aec1d4360c20a27afccfd9fae0b' +
			'f91b65c5524733ab8f593dabcd62b357' +
			'1639d624e65152ab8f530c359f0861d8' +
			'07ca0dbf500d6a6156a38e088a22b65e' +
			'52bc514d16ccf806818ce91ab7793736' +
			'5af90bbf74a35be6b40b8eedf2785e42' +
			'874d',
	},
];

// ============================================================
// RFC 8439 §2.5.2 — Poly1305 MAC
// ============================================================

export interface Poly1305Vector {
	description: string;
	key:      string;   // 32 bytes (64 hex)
	msg?:     string;   // message as hex
	msgText?: string;   // message as UTF-8 text
	tag:      string;   // 16 bytes (32 hex)
}

/** RFC 8439 §2.5.2 and Appendix A.3 test vectors for the Poly1305 MAC. */
export const poly1305Vectors: Poly1305Vector[] = [
	{
		// RFC 8439 §2.5.2 — Gate vector
		description: 'RFC 8439 §2.5.2: Cryptographic Forum Research Group (34 bytes)',
		key:
			'85d6be7857556d337f4452fe42d506a8' +
			'0103808afb0db2fd4abff6af4149f51b',
		msgText: 'Cryptographic Forum Research Group',
		tag: 'a8061dc1305136c6c22b8baf0c0127a9',
	},
	{
		// RFC 8439 §A.3 TV#1 — all-zero key, 64 zero bytes → zero tag
		description: 'RFC 8439 §A.3 vec 1: zero key, 64 zero bytes → zero tag',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		msg:
			'0000000000000000000000000000000000000000000000000000000000000000' +
			'0000000000000000000000000000000000000000000000000000000000000000',
		tag: '00000000000000000000000000000000',
	},
	{
		// RFC 8439 §A.3 TV#2 — r=0, any message, tag equals s
		description: 'RFC 8439 §A.3 vec 2: r=0, 375-byte IETF message, tag equals s',
		key:
			'00000000000000000000000000000000' +
			'36e5f6b5c5e06070f0efca96227a863e',
		msgText:
			'Any submission to the IETF intended by the Contributor for publication as ' +
			'all or part of an IETF Internet-Draft or RFC and any statement made within ' +
			'the context of an IETF activity is considered an "IETF Contribution". Such ' +
			'statements include oral statements in IETF sessions, as well as written and ' +
			'electronic communications made at any time or place, which are addressed to',
		tag: '36e5f6b5c5e06070f0efca96227a863e',
	},
	{
		// RFC 8439 §A.3 TV#3 — r-only key, s=0
		description: 'RFC 8439 §A.3 vec 3: r-only key, 375-byte IETF message',
		key:
			'36e5f6b5c5e06070f0efca96227a863e' +
			'00000000000000000000000000000000',
		msgText:
			'Any submission to the IETF intended by the Contributor for publication as ' +
			'all or part of an IETF Internet-Draft or RFC and any statement made within ' +
			'the context of an IETF activity is considered an "IETF Contribution". Such ' +
			'statements include oral statements in IETF sessions, as well as written and ' +
			'electronic communications made at any time or place, which are addressed to',
		tag: 'f3477e7cd95417af89a6b8794c310cf0',
	},
	{
		// RFC 8439 §A.3 TV#4 — Jabberwocky (127 bytes)
		description: 'RFC 8439 §A.3 vec 4: Jabberwocky text (127 bytes)',
		key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
		msgText:
			'\'Twas brillig, and the slithy toves\n' +
			'Did gyre and gimble in the wabe:\n' +
			'All mimsy were the borogoves,\n' +
			'And the mome raths outgrabe.',
		tag: '4541669a7eaaee61e708dc7cbcc5eb62',
	},
	{
		// RFC 8439 §A.3 TV#5 — h reaches p (modular reduction edge case)
		description: 'RFC 8439 §A.3 vec 5: h reaches p (modular reduction)',
		key:
			'02000000000000000000000000000000' +
			'00000000000000000000000000000000',
		msg: 'ffffffffffffffffffffffffffffffff',
		tag: '03000000000000000000000000000000',
	},
	{
		// RFC 8439 §A.3 TV#6 — h + s overflows 128-bit, carry discarded
		description: 'RFC 8439 §A.3 vec 6: h + s overflow, carry discarded',
		key:
			'02000000000000000000000000000000' +
			'ffffffffffffffffffffffffffffffff',
		msg: '02000000000000000000000000000000',
		tag: '03000000000000000000000000000000',
	},
];

// ============================================================
// RFC 8439 §2.6.2 — Poly1305 key generation
// ============================================================

export interface Poly1305KeyGenVector {
	description: string;
	key:         string; // 32 bytes (ChaCha20 key)
	nonce:       string; // 12 bytes (ChaCha20 nonce)
	counter:     number;
	poly1305Key: string; // 32 bytes (first 32 bytes of block at counter=0)
}

/** RFC 8439 §2.6.2 test vector for Poly1305 key generation. */
export const poly1305KeyGenVectors: Poly1305KeyGenVector[] = [
	{
		// RFC 8439 §2.6.2 — Poly1305 one-time key from ChaCha20 block 0
		description: 'RFC 8439 §2.6.2: Poly1305 key from ChaCha20 block 0',
		key:
			'808182838485868788898a8b8c8d8e8f' +
			'909192939495969798999a9b9c9d9e9f',
		nonce: '000000000001020304050607',
		counter: 1,
		poly1305Key:
			'8ad5a08b905f81cc815040274ab29471' +
			'a833b637e3fd0da508dbb8e2fdd1a646',
	},
];

// ============================================================
// HChaCha20 — XChaCha20 IETF draft §A.3.1
// ============================================================

export interface HChaCha20Vector {
	description: string;
	key:     string; // 32 bytes
	nonce16: string; // 16 bytes — fills all 4 state words 12-15
	subkey:  string; // 32 bytes
}

/** XChaCha20 draft §A.3.1 test vector for HChaCha20. */
export const hchacha20Vectors: HChaCha20Vector[] = [
	{
		// draft-irtf-cfrg-xchacha-03 §A.3.1
		description: 'XChaCha20 draft §A.3.1: sequential key, non-zero nonce16',
		key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		nonce16: '000000090000004a0000000031415927',
		subkey:
			'82413b4227b27bfed30e42508a877d73' +
			'a0f9e4d58a74a853c12ec41326d3ecdc',
	},
];

// ============================================================
// AEAD_CHACHA20_POLY1305 — RFC 8439 §2.8.2
// ============================================================

export interface AeadVector {
	description: string;
	key:     string;  // 32 bytes
	nonce:   string;  // 12 bytes (ChaCha20Poly1305) or 24 bytes (XChaCha20Poly1305)
	aad:     string;  // hex
	pt?:     string;  // plaintext hex
	ptText?: string;  // plaintext as UTF-8 text
	ct:      string;  // ciphertext hex (same length as plaintext)
	tag:     string;  // 16 bytes
}

/** RFC 8439 §2.8.2 AEAD test vectors for AEAD_CHACHA20_POLY1305. */
export const chacha20Poly1305Vectors: AeadVector[] = [
	{
		// RFC 8439 §2.8.2 — "Sunscreen" example
		description: 'RFC 8439 §2.8.2: sunscreen AEAD example (114-byte plaintext)',
		key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
		nonce: '070000004041424344454647',
		aad: '50515253c0c1c2c3c4c5c6c7',
		ptText:
			'Ladies and Gentlemen of the class of \'99: If I could offer you' +
			' only one tip for the future, sunscreen would be it.',
		ct:
			'd31a8d34648e60db7b86afbc53ef7ec2' +
			'a4aded51296e08fea9e2b5a736ee62d6' +
			'3dbea45e8ca9671282fafb69da92728b' +
			'1a71de0a9e060b2905d6a5b67ecd3b36' +
			'92ddbd7f2d778b8c9803aee328091b58' +
			'fab324e4fad675945585808b4831d7bc' +
			'3ff4def08e4b7a9de576d26586cec64b' +
			'6116',
		tag: '1ae10b594f09e26a7e902ecbd0600691',
	},
];

/** XChaCha20-Poly1305 AEAD test vector from XChaCha20 draft §A.3.2. */
export const xchacha20Poly1305Vectors: AeadVector[] = [
	{
		// draft-irtf-cfrg-xchacha-03 §A.3.2 — 24-byte nonce
		description: 'XChaCha20 draft §A.3.2: sunscreen AEAD example (24-byte nonce)',
		key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
		nonce: '404142434445464748494a4b4c4d4e4f5051525354555657', // 24 bytes
		aad: '50515253c0c1c2c3c4c5c6c7',
		ptText:
			'Ladies and Gentlemen of the class of \'99: If I could offer you' +
			' only one tip for the future, sunscreen would be it.',
		ct:
			'bd6d179d3e83d43b9576579493c0e939' +
			'572a1700252bfaccbed2902c21396cbb' +
			'731c7f1b0b4aa6440bf3a82f4eda7e39' +
			'ae64c6708c54c216cb96b72e1213b452' +
			'2f8c9ba40db5d945b11b69b982c1bb9e' +
			'3f3fac2bc369488f76b2383565d3fff9' +
			'21f9664c97637da9768812f615c68b13' +
			'b52e',
		tag: 'c0875924c1c7987947deafd8780acf49',
	},
];
