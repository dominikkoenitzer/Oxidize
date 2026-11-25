import { readFileSync } from "node:fs";
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const site = new URL("../", import.meta.url);
const html = readFileSync(new URL("index.html", site), "utf8");
const unescape = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
const platforms = JSON.parse(unescape(/data-platforms='([^']*)'/.exec(html)[1]));
const name = unescape(/<meta property="og:site_name" content="([^"]*)">/.exec(html)[1]);

// The page itself is retired: its address sends visitors to the app's entry in the portfolio.
const PORTFOLIO = "https://portfolio-izanagi.vercel.app/projects/oxidize";

// A release file under a name that every release keeps: no version in the file name or in the tag.
function stableAsset(url) {
  const m = /^https:\/\/github\.com\/[^/]+\/[^/]+\/releases\/(?:latest\/download|download\/([^/]+))\/([^/]+)$/.exec(url ?? "");
  if (!m) return false;
  const versioned = /\d+\.\d+/;
  return !versioned.test(m[1] ?? "") && !versioned.test(m[2]);
}

// Records what a visitor would see go wrong, and keeps every request on this machine.
// Warnings the browser itself prints about the panel's probes, let through on /diag only: a test machine
// has no graphics card, so the graphics probes fail, and Firefox notes that its fingerprinting protection
// changes the screen size the panel reads.
const PROBE_WARNINGS = [
  /^No available adapters\.$/,
  /Failed to create WebGL context: WebGL creation failed/,
  /Fingerprinting Protection is altering screen\.availWidth/,
];

async function guard(page, { probeWarnings = false } = {}) {
  const problems = [];
  const origin = new URL(test.info().project.use.baseURL).origin;
  await page.route((url) => url.origin !== origin, (route) => {
    problems.push(`request to another site: ${route.request().url()}`);
    return route.abort();
  });
  page.on("console", (m) => {
    if (m.type() !== "error" && m.type() !== "warning") return;
    if (probeWarnings && m.type() === "warning" && PROBE_WARNINGS.some((re) => re.test(m.text()))) return;
    problems.push(`console ${m.type()}: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.push(`uncaught: ${e.message}`));
  page.on("response", (r) => {
    if (r.status() >= 400) problems.push(`${r.status()} ${r.url()}`);
  });
  return problems;
}

async function axe(page) {
  const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  return result.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

test.describe("retired page", () => {
  for (const path of ["/", "/index.html"]) {
    test(`${path} sends visitors to the portfolio`, async ({ request }) => {
      const res = await request.get(path, { maxRedirects: 0 });
      expect(res.status()).toBe(308);
      expect(res.headers().location).toBe(PORTFOLIO);
    });
  }
});

test.describe("links", () => {
  test("every download address leads to a release file that keeps its name", async ({ request }) => {
    const linked = [...html.matchAll(/href="(\/download\/[^"#?]+)"/g)].map((m) => m[1]);
    const paths = [...new Set([...Object.keys(platforms).map((k) => `/download/${k}`), ...linked])];
    const wrong = [];
    for (const path of paths) {
      const res = await request.get(path, { maxRedirects: 0 });
      const location = res.headers().location;
      if (res.status() !== 307 || !stableAsset(location)) wrong.push(`${path}: ${res.status()} ${location ?? ""}`);
    }
    expect(wrong).toEqual([]);
  });

  test("nothing points to the diagnostics page", async ({ request }) => {
    expect(html).not.toMatch(/["'(]\/diag\b/);
    const llms = await request.get("/llms.txt");
    if (llms.ok()) expect(await llms.text()).not.toMatch(/\/diag\b/);
  });
});

test.describe("diagnostics", () => {
  test("the panel measures, shows what it would send and sends nothing", async ({ page }) => {
    test.slow();
    const problems = await guard(page, { probeWarnings: true });
    const res = await page.goto("/diag");
    expect(res.status()).toBe(200);
    expect(res.headers()["x-robots-tag"]).toContain("noindex");
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
    await expect(page).toHaveTitle(`${name} diagnostics`);

    const panel = page.locator("[data-diag-panel]");
    const send = panel.locator("button.primary");
    await expect(send).toBeVisible({ timeout: 40_000 });
    expect(await axe(page)).toEqual([]);

    await send.click();
    await expect(panel.locator('p[role="status"]')).toHaveText(/No address for reports is set up/);
    await panel.getByRole("button", { name: "Close" }).click();
    await expect(panel).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Open the panel again" })).toBeFocused();
    expect(problems).toEqual([]);
  });

  test("the address with a slash at the end works too", async ({ request }) => {
    const res = await request.get("/diag/");
    expect(res.status()).toBe(200);
    expect(res.headers()["x-robots-tag"]).toContain("noindex");
  });
});
