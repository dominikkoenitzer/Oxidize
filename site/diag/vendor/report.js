import { browserFacts, displayFacts, gpuFacts, gpuBench, webgpuFacts, memoryFacts, networkFacts, clip } from "./facts.js";
import { measureFrames, observedVitals } from "./measure.js";
import { captured } from "./capture.js";
import { screenshot } from "./shot.js";

export const SCHEMA_VERSION = 1;

// Small JSON from the app (tier, scale, its own GPU timings). Anything that is not
// a short string, a finite number, a boolean or null is dropped, so an app cannot
// leak more than flat facts through it.
export function flat(obj, maxKeys = 24) {
  const out = {};
  if (!obj || typeof obj !== "object") return out;
  for (const [k, v] of Object.entries(obj).slice(0, maxKeys)) {
    const key = clip(k, 40);
    if (v === null || typeof v === "boolean") out[key] = v;
    else if (typeof v === "number" && Number.isFinite(v)) out[key] = Math.round(v * 1000) / 1000;
    else if (typeof v === "string") out[key] = clip(v, 80);
  }
  return out;
}

async function safe(fn, fallback = {}) {
  try {
    return flat((await fn?.()) ?? {});
  } catch {
    return fallback;
  }
}

/**
 * Measure and assemble the report. Nothing is sent from here.
 * @param {object} o
 * @param {string} o.app       short app id, for example "punds"
 * @param {string} [o.release] build hash or version
 * @param {number} [o.durationMs=10000]
 * @param {() => object} [o.quality]  the tier the app chose, e.g. { tier: "high", scale: 1 }
 * @param {() => object} [o.stats]    the app's own numbers, e.g. { gpuMs: 6.1 }
 * @param {() => HTMLCanvasElement} [o.canvas]
 * @param {() => Promise<HTMLCanvasElement|string>} [o.capture]
 * @param {(p: number) => void} [o.onProgress]
 */
export async function collect(o) {
  const before = await safe(o.quality);
  const frames = await measureFrames(o.durationMs ?? 10000, o.onProgress);
  const [webgpu, shot] = await Promise.all([webgpuFacts(), screenshot({ capture: o.capture, canvas: o.canvas })]);
  const gpu = gpuFacts();
  gpu.webgpu = webgpu;
  gpu.benchMs = gpuBench();
  const { errors, dropped } = captured();
  return {
    v: SCHEMA_VERSION,
    app: clip(o.app, 32),
    release: o.release ? clip(o.release, 40) : null,
    path: clip(location.pathname, 120),
    browser: browserFacts(),
    display: displayFacts(),
    gpu,
    frames,
    quality: { start: before, end: await safe(o.quality) },
    stats: await safe(o.stats),
    vitals: observedVitals(),
    memory: memoryFacts(),
    net: networkFacts(),
    errors,
    errorsDropped: dropped,
    shot: shot.image,
    shotNote: shot.reason ?? null,
    note: "",
  };
}

// What the panel shows as "everything that will be sent": the report with the
// screenshot shortened to its size, so the text stays readable.
export function preview(report) {
  const copy = { ...report };
  if (copy.shot) copy.shot = `[image, ${Math.round((copy.shot.length * 3) / 4 / 1024)} KB, shown below]`;
  return JSON.stringify(copy, null, 2);
}
