import { readFileSync } from "node:fs";
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const site = new URL("../", import.meta.url);
const html = readFileSync(new URL("index.html", site), "utf8");
const unescape = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
const platforms = JSON.parse(unescape(/data-platforms='([^']*)'/.exec(html)[1]));
const name = unescape(/<meta property="og:site_name" content="([^"]*)">/.exec(html)[1]);

// A visitor's machine as the page sees it: the user agent, the platform and the client hints.
const UA = {
  chrome: "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
};
const CLIENTS = {
  windows: { ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${UA.chrome}`, platform: "Win32", hints: { platform: "Windows", architecture: "x86" } },
  "windows-arm": { ua: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${UA.chrome}`, platform: "Win32", hints: { platform: "Windows", architecture: "arm" } },
  mac: { ua: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ${UA.chrome}`, platform: "MacIntel", hints: { platform: "macOS", architecture: "arm" } },
  linux: { ua: `Mozilla/5.0 (X11; Linux x86_64) ${UA.chrome}`, platform: "Linux x86_64", hints: { platform: "Linux", architecture: "x86" } },
  phone: {
    ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
    platform: "iPhone",
    touch: 5,
  },
};

// The download the page should offer each machine, or null where it says the app does not run there.
function offered(client) {
  if (client === "windows-arm") return platforms["windows-arm"] ? "windows-arm" : platforms.windows ? "windows" : null;
  return platforms[client] ? client : null;
}

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

// Waits for the font and every picture in view, so a screenshot shows the page as it settles.
async function settle(page) {
  await page.waitForLoadState("load");
  await page.evaluate(async () => {
    await document.fonts.ready;
    const inView = [...document.images].filter((img) => img.getBoundingClientRect().top < innerHeight);
    await Promise.all(inView.map((img) => img.decode().catch(() => {})));
  });
}

async function axe(page) {
  const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  return result.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

for (const scheme of ["light", "dark"]) {
  test(`the page in ${scheme}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    const problems = await guard(page);
    const res = await page.goto("/");
    expect(res.status()).toBe(200);
    await settle(page);

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, "the page is wider than the screen").toBeLessThanOrEqual(0);
    expect(await axe(page)).toEqual([]);
    await expect(page).toHaveScreenshot(`page-${scheme}.png`);
    expect(problems).toEqual([]);
  });
}

test.describe("downloads", () => {
  for (const [client, machine] of Object.entries(CLIENTS)) {
    test(`a ${client} visitor`, async ({ page }) => {
      await page.addInitScript((m) => {
        const set = (key, value) => Object.defineProperty(Navigator.prototype, key, { get: () => value, configurable: true });
        set("userAgent", m.ua);
        set("platform", m.platform);
        set("maxTouchPoints", m.touch ?? 0);
        set(
          "userAgentData",
          m.hints && {
            platform: m.hints.platform,
            mobile: false,
            getHighEntropyValues: async () => ({ architecture: m.hints.architecture }),
          },
        );
      }, machine);
      const problems = await guard(page);
      await page.goto("/");
      await settle(page);

      const key = offered(client);
      const primary = page.locator("#primary");
      if (!key) {
        await expect(page.locator("#away")).toBeVisible();
        expect(problems).toEqual([]);
        return;
      }
      await expect(page.locator("#away")).toBeHidden();

      // Where the page offers a terminal install for this machine, it shows that in place of the button,
      // the buttons further down lead to it, and the file stays one link away inside it.
      const term = page.locator(`#install-${key}`);
      let download = primary;
      if (await term.count()) {
        await expect(term).toBeVisible();
        await expect(primary).toBeHidden();
        const label = await term.getAttribute("data-button");
        for (const button of await page.locator(".closing [data-primary]").all()) {
          await expect(button).toHaveAttribute("href", `#install-${key}`);
          await expect(button).toHaveText(label);
        }
        download = term.locator(`a[href="/download/${key}"]`);
        await expect(download).toBeVisible();
      } else {
        await expect(primary).toHaveAttribute("href", `/download/${key}`);
        await expect(primary).toHaveText(`Download for ${platforms[key]}`);
      }

      // The click goes to this site and its answer is kept; the browser then gets "no content" and stays on the page.
      let answered;
      const answer = new Promise((resolve) => (answered = resolve));
      await page.route("**/download/**", async (route) => {
        const res = await route.fetch({ maxRedirects: 0 });
        answered({ url: route.request().url(), status: res.status(), location: res.headers().location });
        await route.fulfill({ status: 204 });
      });
      await download.click();
      const served = await answer;
      expect(new URL(served.url).pathname).toBe(`/download/${key}`);
      expect(served.status).toBe(307);
      expect(stableAsset(served.location), `${served.location} keeps its name from release to release`).toBe(true);
      expect(problems).toEqual([]);
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

  test("every address on the page answers", async ({ request }) => {
    const refs = [...html.matchAll(/\s(?:href|src)="([^"]+)"/g), ...html.matchAll(/\ssrcset="([^"]+)"/g)]
      .flatMap((m) => m[1].split(",").map((part) => part.trim().split(/\s+/)[0]))
      .map(unescape)
      .filter((ref) => ref && !/^(?:https?:|mailto:|data:|#|\/download\/)/.test(ref));
    const wrong = [];
    for (const ref of new Set(refs)) {
      const res = await request.get(new URL(ref, "http://x/").pathname, { maxRedirects: 0 });
      if (res.status() >= 400) wrong.push(`${ref}: ${res.status()}`);
    }
    const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    for (const [, id] of html.matchAll(/href="#([^"]+)"/g)) if (!ids.has(id)) wrong.push(`#${id}: no such part of the page`);
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
