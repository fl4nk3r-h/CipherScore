import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  use: {
    baseURL: "http://localhost:3100",
  },
  webServer: {
    command: "pnpm dev -- --port 3100",
    url: "http://localhost:3100",
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
