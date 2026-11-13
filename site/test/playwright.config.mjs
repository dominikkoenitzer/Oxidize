import { defineConfig } from "@playwright/test";

const PORT = 4173;

// The four sizes of the screenshot sheet, plus 360 px for the smallest phones in use.
const SIZES = [
  { name: "390", use: { viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, hasTouch: true } },
  { name: "360", use: { viewport: { width: 360, height: 780 }, deviceScaleFactor: 3, hasTouch: true } },
  { name: "768", use: { viewport: { width: 768, height: 1024 }, deviceScaleFactor: 2, hasTouch: true } },
  { name: "1440", use: { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 } },
  { name: "2560", use: { viewport: { width: 2560, height: 1440 }, deviceScaleFactor: 1 } },
];
const ENGINES = ["chromium", "firefox", "webkit"];
const TEST_TIMEOUT = 60_000;

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  snapshotPathTemplate: "snapshots/{arg}-{projectName}-{platform}{ext}",
  timeout: TEST_TIMEOUT,
  forbidOnly: !!process.env.CI,
  workers: process.env.CI ? 4 : 2,
  reporter: process.env.CI ? [["list"], ["html", { outputFolder: "report", open: "never" }]] : [["list"]],
  expect: {
    // A first screenshot needs two matching captures, and WebKit on a CI runner takes longer than the
    // five second default for a tall phone page, so a screenshot may use the whole test's time.
    toHaveScreenshot: { animations: "disabled", scale: "css", maxDiffPixelRatio: 0.01, timeout: TEST_TIMEOUT },
  },
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    reducedMotion: "reduce",
    trace: "off",
  },
  projects: ENGINES.flatMap((browserName) =>
    SIZES.map((size) => ({ name: `${browserName}-${size.name}`, use: { browserName, ...size.use } })),
  ),
  webServer: {
    command: `node serve.mjs ${PORT}`,
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
