// Serves the site folder the way the host does: the routes, redirects and headers in vercel.json,
// index.html for a folder, and nothing that .vercelignore keeps off the site.
//   node serve.mjs [port]

import { createServer } from "node:http";
import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const port = Number(process.argv[2] ?? process.env.PORT ?? 4173);
const config = JSON.parse(readFileSync(join(root, "vercel.json"), "utf8"));
const ignored = existsSync(join(root, ".vercelignore"))
  ? readFileSync(join(root, ".vercelignore"), "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim().replace(/^\/|\/$/g, ""))
      .filter((l) => l && !l.startsWith("#"))
  : [];

const types = {
  ".html": "text/html; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".webp": "image/webp",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".zip": "application/zip",
};

// A source such as "/update/:file" or "/diag/(.*)" as a whole-path pattern, with ":file" as a named group.
function pattern(source) {
  const body = source
    .split(/(:\w+|\(\.\*\))/)
    .map((part) => {
      if (part === "(.*)") return "(.*)";
      if (/^:\w+$/.test(part)) return `(?<${part.slice(1)}>[^/]+)`;
      return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("");
  return new RegExp(`^${body}$`);
}

// "routes" is the older form one site uses: a regex, an optional status and headers, and "continue".
const routes = (config.routes ?? []).map((r) => ({ ...r, re: new RegExp(r.src) }));
const redirects = (config.redirects ?? []).map((r) => ({ ...r, re: pattern(r.source) }));
const headerRules = (config.headers ?? []).map((h) => ({ ...h, re: pattern(h.source) }));

const isIgnored = (rel) => ignored.some((rule) => rule === rel || rel.startsWith(`${rule}/`));

function serveFile(path, res) {
  const rel = normalize(path).split(sep).join("/").replace(/^\/+/, "");
  if (rel.startsWith("..") || isIgnored(rel)) return notFound(res);
  let file = join(root, rel);
  if (existsSync(file) && statSync(file).isDirectory()) file = join(file, "index.html");
  if (!existsSync(file) || !statSync(file).isFile()) return notFound(res);
  if (!res.hasHeader("content-type")) res.setHeader("content-type", types[extname(file)] ?? "application/octet-stream");
  res.writeHead(200);
  res.end(readFileSync(file));
}

function notFound(res) {
  res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  res.end("not found");
}

createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);

  for (const route of routes) {
    const m = route.re.exec(path);
    if (!m) continue;
    for (const [key, value] of Object.entries(route.headers ?? {})) {
      res.setHeader(key, value.replace(/\$(\d)/g, (_, i) => m[Number(i)] ?? ""));
    }
    if (route.continue) continue;
    if (route.status) {
      res.writeHead(route.status);
      return res.end();
    }
    return serveFile(route.dest ?? path, res);
  }

  for (const rule of headerRules) {
    if (rule.re.test(path)) rule.headers.forEach((h) => res.setHeader(h.key, h.value));
  }
  for (const r of redirects) {
    const m = r.re.exec(path);
    if (!m) continue;
    const to = r.destination.replace(/:(\w+)/g, (all, name) => m.groups?.[name] ?? all);
    res.writeHead(r.permanent ? 308 : 307, { location: to });
    return res.end();
  }
  serveFile(path, res);
}).listen(port, "127.0.0.1", () => console.log(`site on http://127.0.0.1:${port}`));
