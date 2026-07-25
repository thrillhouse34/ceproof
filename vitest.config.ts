import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // 60s (not the previous 20s): the real-Chrome PDF-rendering tests
    // (tests/report/pdf.test.ts, tests/cli/report.test.ts,
    // tests/integration/customerJourney.test.ts step 6) render in ~9.5s warm,
    // but a cold Chrome launch on a machine that actually has a browser
    // installed can exceed 20s outright -- these tests are silently skipped
    // in this sandbox (no browser present), so that headroom problem never
    // surfaced here. Every other test in the suite finishes in well under a
    // second either way, so this ceiling only matters for the slow ones.
    testTimeout: 60000,
  },
});
