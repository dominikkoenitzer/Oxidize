// Error capture. Call installCapture() as early as possible at boot so the report
// also holds errors from before the diagnostic page was opened. Messages and stacks
// are clipped, and every URL in them loses its query and fragment (tokens live there)
// and any foreign path (only the origin of other hosts is kept).

const KEY = "__diagCapture";
const MAX = 50;

function state() {
  const g = globalThis;
  if (!g[KEY]) g[KEY] = { installed: false, start: performance.now(), items: [], dropped: 0 };
  return g[KEY];
}

export function scrubUrls(text, origin = globalThis.location?.origin ?? "") {
  return String(text).replace(/\b(?:blob:)?(?:https?|file):\/\/[^\s)'"]+/g, (url) => {
    if (url.startsWith("file:")) return "file://…";
    try {
      if (url.startsWith("blob:")) return "blob:" + new URL(url.slice(5)).origin;
      const u = new URL(url);
      if (u.origin !== origin) return u.origin;
      // keep the line:column of stack frames, which a query string would otherwise swallow
      const lc = url.match(/:\d+:\d+$/)?.[0] ?? "";
      return u.origin + (u.pathname.endsWith(lc) ? u.pathname : u.pathname + lc);
    } catch {
      return "…";
    }
  });
}

export function record(kind, message, stack) {
  const s = state();
  if (s.items.length >= MAX) {
    s.dropped += 1;
    return;
  }
  s.items.push({
    kind,
    message: scrubUrls(String(message ?? "")).slice(0, 300),
    stack: stack ? scrubUrls(String(stack)).slice(0, 1500) : null,
    t: Math.round(performance.now() - s.start),
  });
}

function describe(value) {
  if (value instanceof Error) return [value.name + ": " + value.message, value.stack];
  if (typeof value === "string") return [value, null];
  try {
    return [JSON.stringify(value).slice(0, 300), null];
  } catch {
    return [String(value), null];
  }
}

export function installCapture(win = globalThis) {
  const s = state();
  if (s.installed || !win.addEventListener) return;
  s.installed = true;
  win.addEventListener("error", (e) => {
    // resource load failures arrive here too, with a target instead of a message
    if (e.target && e.target !== win && e.target.tagName) {
      record("resource", `${e.target.tagName.toLowerCase()} failed: ${e.target.src || e.target.href || ""}`, null);
      return;
    }
    const [m, st] = e.error ? describe(e.error) : [e.message, null];
    record("error", m, st);
  }, true);
  win.addEventListener("unhandledrejection", (e) => {
    const [m, st] = describe(e.reason);
    record("rejection", m, st);
  });
  const original = console.error;
  console.error = function (...args) {
    const first = args.find((a) => a instanceof Error);
    record("console", args.map((a) => describe(a)[0]).join(" "), first ? first.stack : null);
    return original.apply(this, args);
  };
}

export function captured() {
  const s = state();
  return { errors: s.items.slice(), dropped: s.dropped };
}

export function resetCapture() {
  const s = state();
  s.items.length = 0;
  s.dropped = 0;
}
