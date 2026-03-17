// test/vectors/serpent.ts
//
// SerpentStream round-trip fixture.

export const serpentStreamFixture = {
	description: 'SerpentStream round-trip fixture — 3 chunks at 1024-byte chunk size',
	key: '00'.repeat(32),
	plaintext: 'ab'.repeat(3072),  // 3072 bytes = 3 × 1024-byte chunks
	chunkSize: 1024,
};
