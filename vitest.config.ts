import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    testTimeout: 600_000,
    include: ['test/unit/**/*.test.ts'],
  },
})
