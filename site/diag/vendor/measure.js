import { round } from "./facts.js";

// Frame pacing as the visitor gets it: requestAnimationFrame deltas while the app
// keeps rendering. The refresh rate is read from the fastest steady frames, so a
// 120 Hz display reports 120 even when the app runs slower.
export function measureFrames(durationMs, onProgress) {
  return new Promise((resolve) => {
    const deltas = [];
    let hidden = document.visibilityState === "hidden";
    const onVis = () => {
      if (document.visibilityState === "hidden") hidden = true;
    };
    document.addEventListener("visibilitychange", onVis);
    let start = null;
    let last = null;
    let lastTick = -1;
    const step = (t) => {
      if (start === null) start = last = t;
      else {
        deltas.push(t - last);
        last = t;
      }
      const elapsed = t - start;
      const second = Math.floor(elapsed / 1000);
      if (onProgress && second !== lastTick) {
        lastTick = second;
        onProgress(Math.min(1, elapsed / durationMs));
      }
      if (elapsed >= durationMs) {
        document.removeEventListener("visibilitychange", onVis);
        resolve(summarizeFrames(deltas, durationMs, hidden));
      } else requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

export function percentile(sorted, p) {
  if (!sorted.length) return null;
  const i = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[i];
}

export function summarizeFrames(deltas, durationMs, hidden = false) {
  const sorted = deltas.slice().sort((a, b) => a - b);
  const fast = percentile(sorted, 5);
  return {
    durationMs,
    count: deltas.length,
    p50: n(percentile(sorted, 50)),
    p95: n(percentile(sorted, 95)),
    p99: n(percentile(sorted, 99)),
    max: n(sorted[sorted.length - 1] ?? null),
    over50: deltas.filter((d) => d > 50).length,
    refreshHz: fast ? nearestRefresh(1000 / fast) : null,
    hidden,
  };
}

const RATES = [24, 30, 48, 50, 60, 72, 75, 90, 100, 120, 144, 165, 170, 175, 180, 200, 240, 360];
function nearestRefresh(hz) {
  let best = RATES[0];
  for (const r of RATES) if (Math.abs(r - hz) < Math.abs(best - hz)) best = r;
  // a rate far from every known panel rate is reported as measured
  return Math.abs(best - hz) / best < 0.06 ? best : Math.round(hz);
}

function n(v) {
  return v === null || v === undefined ? null : round(v, 2);
}

// Page vitals from the browser's own buffered entries. Engines that lack an
// entry type report null for it rather than a guess.
export function vitals() {
  const out = { ttfb: null, fcp: null, lcp: null, cls: null, inp: null, load: null };
  const nav = performance.getEntriesByType?.("navigation")?.[0];
  if (nav) {
    out.ttfb = round(nav.responseStart, 0);
    out.load = nav.loadEventEnd > 0 ? round(nav.loadEventEnd, 0) : null;
  }
  const fcp = performance.getEntriesByName?.("first-contentful-paint")?.[0];
  if (fcp) out.fcp = round(fcp.startTime, 0);
  return out;
}

// Observers that need buffered entries are started at install time so LCP and
// layout shifts from the first seconds are kept.
const OBS = "__diagVitals";
export function installVitals() {
  const g = globalThis;
  if (g[OBS] || typeof PerformanceObserver === "undefined") return;
  const supported = PerformanceObserver.supportedEntryTypes || [];
  const v = (g[OBS] = { lcp: null, cls: 0, clsSupported: supported.includes("layout-shift"), inp: null });
  const watch = (type, fn, extra = {}) => {
    if (!supported.includes(type)) return;
    try {
      new PerformanceObserver((list) => list.getEntries().forEach(fn)).observe({ type, buffered: true, ...extra });
    } catch {
      // an engine that lists a type but rejects the options is simply skipped
    }
  };
  watch("largest-contentful-paint", (e) => (v.lcp = e.startTime));
  watch("layout-shift", (e) => {
    if (!e.hadRecentInput) v.cls += e.value;
  });
  watch("event", (e) => {
    if (e.interactionId) v.inp = Math.max(v.inp ?? 0, e.duration);
  }, { durationThreshold: 16 });
}

export function observedVitals() {
  const out = vitals();
  const v = globalThis[OBS];
  if (v) {
    out.lcp = v.lcp === null ? null : round(v.lcp, 0);
    out.cls = v.clsSupported ? round(v.cls, 4) : null;
    out.inp = v.inp === null ? null : round(v.inp, 0);
  }
  return out;
}
