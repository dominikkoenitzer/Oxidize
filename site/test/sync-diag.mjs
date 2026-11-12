// Copies the diagnostic panel from a checkout of its repository into ../diag/vendor,
// byte for byte, and records where each file came from in diag-upstream.json.
//
//   node sync-diag.mjs <path to the diag checkout>   copy and record
//   node sync-diag.mjs --check                       verify only
//
// The files come from the checkout's last commit, never its working tree. --check (run in CI)
// fails when a copied file no longer matches its recorded hash: change it by syncing again.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const target = join(here, "..", "diag", "vendor");
const manifestPath = join(here, "diag-upstream.json");
// Line endings are left out of the hash, since a checkout may turn them into CRLF (core.autocrlf, eol=crlf).
const sha256 = (buf) => createHash("sha256").update(buf.toString("utf8").replace(/\r\n/g, "\n")).digest("hex");

if (process.argv[2] === "--check") {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const recorded = Object.keys(manifest.files).sort();
  const present = readdirSync(target).sort();
  const bad = recorded.filter((n) => !present.includes(n) || sha256(readFileSync(join(target, n))) !== manifest.files[n]);
  const extra = present.filter((n) => !recorded.includes(n));
  if (bad.length || extra.length) {
    if (bad.length) console.error(`diag files changed by hand or missing: ${bad.join(", ")}`);
    if (extra.length) console.error(`diag files with no record: ${extra.join(", ")}`);
    console.error("Sync them again with test/sync-diag.mjs instead.");
    process.exit(1);
  }
  console.log(`diag client matches upstream ${manifest.commit.slice(0, 7)} (${recorded.length} files)`);
  process.exit(0);
}

const source = process.argv[2];
if (!source) {
  console.error("usage: node sync-diag.mjs <path to the diag checkout> | --check");
  process.exit(2);
}
const git = (...args) => execFileSync("git", ["-C", source, ...args]);
const commit = git("rev-parse", "HEAD").toString().trim();
// Only the panel, the error capture and the measurements, with the files they import: the page loads
// them as they are, with no bundler, and the telemetry beacon (which needs one) stays out.
const show = (name) => git("show", `HEAD:src/client/${name}`);
const names = [];
const queue = ["panel.js", "capture.js", "measure.js"];
while (queue.length) {
  const name = queue.shift();
  if (names.includes(name)) continue;
  names.push(name);
  for (const [, dep] of show(name).toString().matchAll(/^\s*(?:import|export)\s+(?:[\w$*{},\s]+?\s+from\s+)?["']([^"']+)["']/gm)) {
    if (!dep.startsWith("./")) {
      console.error(`${name} imports ${dep}, which a page cannot load without a bundler`);
      process.exit(1);
    }
    queue.push(dep.slice(2));
  }
}
names.sort();

rmSync(target, { recursive: true, force: true });
mkdirSync(target, { recursive: true });
const files = {};
for (const name of names) {
  const content = show(name);
  writeFileSync(join(target, name), content);
  files[name] = sha256(content);
}
writeFileSync(manifestPath, `${JSON.stringify({ commit, path: "src/client", files }, null, 2)}\n`);
console.log(`copied ${names.length} files from ${commit.slice(0, 7)}`);
