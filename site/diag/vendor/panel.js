import { collect, preview } from "./report.js";

const TEXT = {
  en: {
    title: "Diagnostics",
    intro:
      "This page measures for {s} seconds how this site runs on your device, then shows you everything it would send. Nothing leaves your device unless you press Send. No cookies, no identifiers, no IP address stored.",
    measuring: "Measuring… {n} s left. Keep this tab open; you can look around as usual.",
    gpu: "Graphics",
    density: "Pixel density",
    frames: "Frame time (median / slowest 5%)",
    refresh: "Fastest steady frame rate",
    bench: "Graphics test (lower is faster)",
    tier: "Quality chosen",
    errors: "Errors",
    none: "none",
    unknown: "not available",
    details: "Everything that will be sent",
    shot: "Include this screenshot",
    noShot: "No screenshot: {r}.",
    noteLabel: "What looks wrong? (optional, please no names or addresses)",
    send: "Send",
    sending: "Sending…",
    close: "Close",
    again: "Measure again",
    sent: "Sent. Your code:",
    sentHint: "Read this code out to the person helping you.",
    failed: "Sending failed ({e}). Nothing was stored. You can try again.",
  },
  de: {
    title: "Diagnose",
    intro:
      "Diese Seite misst {s} Sekunden lang, wie sie auf deinem Gerät läuft, und zeigt dir danach alles, was gesendet würde. Ohne Klick auf «Senden» verlässt nichts dein Gerät. Keine Cookies, keine Kennungen, keine gespeicherte IP-Adresse.",
    measuring: "Messung läuft… noch {n} s. Lass den Tab offen; du kannst dich wie gewohnt umsehen.",
    gpu: "Grafik",
    density: "Pixeldichte",
    frames: "Bildzeit (Median / langsamste 5 %)",
    refresh: "Schnellste stabile Bildrate",
    bench: "Grafiktest (tiefer ist schneller)",
    tier: "Gewählte Qualität",
    errors: "Fehler",
    none: "keine",
    unknown: "nicht verfügbar",
    details: "Alles, was gesendet wird",
    shot: "Diesen Screenshot mitsenden",
    noShot: "Kein Screenshot: {r}.",
    noteLabel: "Was sieht falsch aus? (freiwillig, bitte keine Namen oder Adressen)",
    send: "Senden",
    sending: "Wird gesendet…",
    close: "Schliessen",
    again: "Neu messen",
    sent: "Gesendet. Dein Code:",
    sentHint: "Lies diesen Code der Person vor, die dir hilft.",
    failed: "Senden fehlgeschlagen ({e}). Es wurde nichts gespeichert. Du kannst es nochmals versuchen.",
  },
};

const CSS = `
:host { all: initial; }
.card { position: fixed; z-index: 2147483647; right: 16px; top: 16px; box-sizing: border-box;
  width: min(440px, calc(100vw - 32px)); max-height: calc(100vh - 32px); overflow: auto;
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #f2f2f2;
  background: rgba(20, 20, 24, 0.96); border: 1px solid #3a3a42; border-radius: 12px;
  padding: 16px; box-shadow: 0 8px 32px rgba(0,0,0,.45); }
h2 { font-size: 16px; margin: 0 0 8px; font-weight: 600; }
p { margin: 0 0 10px; }
dl { display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; margin: 0 0 12px; }
dt { color: #b9b9c4; } dd { margin: 0; word-break: break-word; }
details { margin: 0 0 12px; } summary { cursor: pointer; color: #cfe3ff; }
pre { font: 12px/1.35 ui-monospace, Consolas, monospace; white-space: pre-wrap; word-break: break-all;
  background: #0d0d10; border: 1px solid #2c2c33; border-radius: 8px; padding: 8px; max-height: 240px; overflow: auto; }
img { display: block; max-width: 100%; max-height: 160px; width: auto; height: auto; object-fit: contain; border-radius: 8px; margin: 6px 0 4px; border: 1px solid #2c2c33; }
label { display: block; margin: 0 0 10px; }
textarea { box-sizing: border-box; width: 100%; min-height: 56px; margin-top: 4px; font: inherit; color: inherit;
  background: #0d0d10; border: 1px solid #45454f; border-radius: 8px; padding: 6px 8px; resize: vertical; }
.row { display: flex; gap: 8px; flex-wrap: wrap; }
button { font: inherit; font-weight: 600; border-radius: 8px; padding: 8px 14px; cursor: pointer;
  border: 1px solid #5a5a66; background: #26262d; color: #f2f2f2; }
button.primary { background: #e8e8ee; color: #111; border-color: #e8e8ee; }
button:disabled { opacity: .55; cursor: default; }
button:focus-visible, summary:focus-visible, textarea:focus-visible, input:focus-visible { outline: 2px solid #8ab4ff; outline-offset: 2px; }
.code { font: 700 28px/1.2 ui-monospace, Consolas, monospace; letter-spacing: .12em; margin: 4px 0 8px; }
.bar { height: 4px; background: #33333b; border-radius: 2px; overflow: hidden; margin: 8px 0 0; }
.bar > i { display: block; height: 100%; width: 0; background: #8ab4ff; transition: width .9s linear; }
.err { color: #ffb4a8; }
@media (prefers-reduced-motion: reduce) { .bar > i { transition: none; } }
@media (prefers-color-scheme: light) {
  .card { color: #16161a; background: rgba(250, 250, 252, 0.97); border-color: #c9c9d2; }
  dt { color: #55555f; } summary { color: #1d4ed8; } .err { color: #b42318; }
  pre, textarea { background: #fff; border-color: #c9c9d2; }
  button { background: #f0f0f4; color: #16161a; border-color: #b4b4be; }
  button.primary { background: #16161a; color: #fff; border-color: #16161a; }
  .bar { background: #dcdce3; } .bar > i { background: #1d4ed8; }
}`;

function fill(s, vars) {
  return s.replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? ""));
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, "");
    else if (v !== false && v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

function tierText(q, t) {
  const end = q?.end ?? {};
  const parts = Object.entries(end).map(([k, v]) => `${k} ${v}`);
  return parts.length ? parts.join(", ") : t.unknown;
}

/**
 * Show the panel and run one measurement. Returns { close }.
 * Options are those of collect() plus:
 * @param {string} o.endpoint  full URL of POST /v1/diag
 * @param {"en"|"de"} [o.lang="en"]
 * @param {(report: object) => void} [o.onReport]  called with the measured report (tests, local export)
 */
export function mountPanel(o) {
  const t = TEXT[o.lang] ?? TEXT.en;
  const host = el("div", { "data-diag-panel": true });
  const root = host.attachShadow({ mode: "open" });
  // a constructed sheet is not an inline style, so sites with a strict style-src keep working
  try {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    root.adoptedStyleSheets = [sheet];
  } catch {
    root.append(el("style", { text: CSS }));
  }
  const card = el("section", { class: "card small", role: "dialog", "aria-modal": "false", "aria-labelledby": "diag-title" });
  root.append(card);
  document.body.append(host);
  // vitals of a page view with the panel open describe the panel, not the site
  globalThis.__diagPanelOpened = true;

  const seconds = Math.round((o.durationMs ?? 10000) / 1000);
  let closed = false;
  const close = () => {
    closed = true;
    host.remove();
    o.onClose?.();
  };
  root.addEventListener("keydown", (e) => {
    if (e.key === "Escape") close();
  });

  const title = el("h2", { id: "diag-title", text: t.title });

  async function run() {
    card.className = "card small";
    const status = el("p", { role: "status", "aria-live": "polite", text: fill(t.measuring, { n: seconds }) });
    const bar = el("i");
    card.replaceChildren(title, el("p", { text: fill(t.intro, { s: seconds }) }), status, el("div", { class: "bar", "aria-hidden": "true" }, bar));
    const report = await collect({
      ...o,
      onProgress: (p) => {
        status.textContent = fill(t.measuring, { n: Math.max(0, Math.ceil(seconds * (1 - p))) });
        bar.style.width = `${Math.round(p * 100)}%`;
      },
    });
    if (closed) return;
    o.onReport?.(report);
    show(report);
  }

  function show(report) {
    card.className = "card";
    const g = report.gpu;
    const f = report.frames;
    const dl = el("dl", {},
      el("dt", { text: t.gpu }), el("dd", { text: g.renderer ?? t.unknown }),
      el("dt", { text: t.density }), el("dd", { text: `${report.display.dpr}× · ${report.display.viewport.join(" × ")} px` }),
      el("dt", { text: t.frames }), el("dd", { text: f.p50 === null ? t.unknown : `${f.p50} / ${f.p95} ms` }),
      el("dt", { text: t.refresh }), el("dd", { text: f.refreshHz ? `${f.refreshHz} Hz` : t.unknown }),
      el("dt", { text: t.bench }), el("dd", { text: g.benchMs === null || g.benchMs === undefined ? t.unknown : `${g.benchMs} ms` }),
      el("dt", { text: t.tier }), el("dd", { text: tierText(report.quality, t) }),
      el("dt", { text: t.errors }), el("dd", { text: report.errors.length ? String(report.errors.length) : t.none }),
    );
    const pre = el("pre", { tabindex: "0", "aria-label": t.details });
    const note = el("textarea", { id: "diag-note", maxlength: "500" });
    const shotBox = el("input", { type: "checkbox", id: "diag-shot", checked: !!report.shot });
    const refresh = () => {
      const sending = { ...report, note: note.value.slice(0, 500), shot: shotBox.checked ? report.shot : null };
      pre.textContent = preview(sending);
      return sending;
    };
    note.addEventListener("input", refresh);
    shotBox.addEventListener("change", refresh);
    refresh();

    const shotPart = report.shot
      ? el("div", {}, el("img", { src: report.shot, alt: "" }), el("label", {}, shotBox, " ", t.shot))
      : el("p", { text: fill(t.noShot, { r: report.shotNote ?? t.unknown }) });
    const msg = el("p", { role: "status", "aria-live": "polite" });
    const send = el("button", { class: "primary", type: "button", text: t.send });
    const again = el("button", { type: "button", text: t.again, onclick: () => run() });
    const closeBtn = el("button", { type: "button", text: t.close, onclick: close });

    send.addEventListener("click", async () => {
      send.disabled = true;
      send.textContent = t.sending;
      msg.className = "";
      msg.textContent = "";
      try {
        const res = await fetch(o.endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(refresh()),
          credentials: "omit",
          referrerPolicy: "no-referrer",
          cache: "no-store",
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok || !body.code) throw new Error(body.error || `HTTP ${res.status}`);
        done(body.code);
      } catch (e) {
        msg.className = "err";
        msg.textContent = fill(t.failed, { e: String(e?.message ?? e).slice(0, 80) });
        send.disabled = false;
        send.textContent = t.send;
      }
    });

    card.replaceChildren(
      title,
      dl,
      shotPart,
      el("details", {}, el("summary", { text: t.details }), pre),
      el("label", { for: "diag-note" }, t.noteLabel, note),
      msg,
      el("div", { class: "row" }, send, again, closeBtn),
    );
    send.focus();
  }

  function done(code) {
    const shown = code.slice(0, 3) + "-" + code.slice(3);
    const closeBtn = el("button", { type: "button", text: t.close, onclick: close });
    card.className = "card small";
    card.replaceChildren(
      title,
      el("p", { role: "status", text: t.sent }),
      el("div", { class: "code", "aria-label": code.split("").join(" "), "data-code": code, text: shown }),
      el("p", { text: t.sentHint }),
      el("div", { class: "row" }, closeBtn),
    );
    closeBtn.focus();
  }

  run();
  return { close };
}
