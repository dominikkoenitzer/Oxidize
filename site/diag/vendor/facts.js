// Device facts for the diagnostic report. Everything here is read once and reduced
// to coarse values: the user agent string is parsed on the device and never sent.

export function browserFacts(nav = navigator) {
  const ua = nav.userAgent || "";
  let engine = "other";
  if (/Gecko\/\d/.test(ua) && /Firefox\/\d/.test(ua)) engine = "gecko";
  // browsers on iOS carry CriOS/FxiOS/EdgiOS but never "Chrome/": they are WebKit
  else if (/Chrome\/|Chromium\//.test(ua)) engine = "blink";
  else if (/AppleWebKit\//.test(ua)) engine = "webkit";

  let browser = "other";
  let version = null;
  const pick = (name, re) => {
    const m = ua.match(re);
    if (m) {
      browser = name;
      version = Number(m[1]);
      return true;
    }
    return false;
  };
  if (nav.brave && typeof nav.brave.isBrave === "function") pick("brave", /Chrome\/(\d+)/);
  else
    pick("edge", /Edg(?:e|A|iOS)?\/(\d+)/) ||
      pick("opera", /OPR\/(\d+)/) ||
      pick("samsung", /SamsungBrowser\/(\d+)/) ||
      pick("firefox", /(?:Firefox|FxiOS)\/(\d+)/) ||
      pick("chrome", /(?:Chrome|CriOS)\/(\d+)/) ||
      pick("safari", /Version\/(\d+)[.\d]* (?:Mobile\/\S+ )?Safari\//);

  let os = "other";
  if (/Windows NT/.test(ua)) os = "windows";
  else if (/iPhone|iPad|iPod/.test(ua)) os = "ios";
  else if (/Mac OS X/.test(ua)) os = "macos";
  else if (/Android/.test(ua)) os = "android";
  else if (/CrOS/.test(ua)) os = "chromeos";
  else if (/Linux/.test(ua)) os = "linux";

  return { engine, browser, version: Number.isFinite(version) ? version : null, os };
}

function media(q) {
  try {
    return matchMedia(q).matches;
  } catch {
    return false;
  }
}

export function displayFacts(win = window) {
  const s = win.screen || {};
  const gamut = media("(color-gamut: rec2020)") ? "rec2020" : media("(color-gamut: p3)") ? "p3" : "srgb";
  return {
    dpr: round(win.devicePixelRatio || 1, 3),
    viewport: [win.innerWidth, win.innerHeight],
    screen: [s.width || 0, s.height || 0],
    avail: [s.availWidth || 0, s.availHeight || 0],
    colorDepth: s.colorDepth || null,
    gamut,
    hdr: media("(dynamic-range: high)"),
    reducedMotion: media("(prefers-reduced-motion: reduce)"),
    dark: media("(prefers-color-scheme: dark)"),
    pointer: media("(pointer: fine)") ? "fine" : media("(pointer: coarse)") ? "coarse" : "none",
    touchPoints: navigator.maxTouchPoints || 0,
  };
}

export function gpuFacts(doc = document) {
  const out = {
    webgl2: false,
    webgl1: false,
    vendor: null,
    renderer: null,
    maxTexture: null,
    maxSamples: null,
    timerQuery: false,
    floatBuffer: false,
    antialias: null,
  };
  const canvas = doc.createElement("canvas");
  canvas.width = canvas.height = 4;
  let gl = null;
  try {
    gl = canvas.getContext("webgl2");
    out.webgl2 = !!gl;
    if (!gl) {
      gl = canvas.getContext("webgl");
      out.webgl1 = !!gl;
    } else out.webgl1 = true;
  } catch {
    gl = null;
  }
  if (!gl) return out;
  try {
    const info = gl.getExtension("WEBGL_debug_renderer_info");
    out.vendor = clip(String(gl.getParameter(info ? info.UNMASKED_VENDOR_WEBGL : gl.VENDOR)), 120);
    out.renderer = clip(String(gl.getParameter(info ? info.UNMASKED_RENDERER_WEBGL : gl.RENDERER)), 200);
    out.maxTexture = gl.getParameter(gl.MAX_TEXTURE_SIZE);
    if (out.webgl2) out.maxSamples = gl.getParameter(gl.MAX_SAMPLES);
    out.timerQuery = !!gl.getExtension(out.webgl2 ? "EXT_disjoint_timer_query_webgl2" : "EXT_disjoint_timer_query");
    out.floatBuffer = !!gl.getExtension(out.webgl2 ? "EXT_color_buffer_float" : "WEBGL_color_buffer_float");
    const attrs = gl.getContextAttributes();
    out.antialias = attrs ? !!attrs.antialias : null;
  } catch {
    // a context that throws on reads is reported with what was read so far
  }
  try {
    gl.getExtension("WEBGL_lose_context")?.loseContext();
  } catch {
    // nothing to free
  }
  return out;
}

export async function webgpuFacts(timeoutMs = 1000) {
  const gpu = typeof navigator !== "undefined" ? navigator.gpu : undefined;
  if (!gpu || typeof gpu.requestAdapter !== "function") return null;
  try {
    const adapter = await Promise.race([gpu.requestAdapter(), sleep(timeoutMs).then(() => null)]);
    if (!adapter) return { adapter: false };
    const info = adapter.info || (adapter.requestAdapterInfo ? await adapter.requestAdapterInfo() : {});
    return {
      adapter: true,
      vendor: clip(info.vendor || "", 60) || null,
      architecture: clip(info.architecture || "", 60) || null,
      fallback: !!(info.isFallbackAdapter ?? adapter.isFallbackAdapter),
    };
  } catch {
    return { adapter: false };
  }
}

export function memoryFacts() {
  const mem = performance.memory;
  return {
    deviceMemory: navigator.deviceMemory ?? null,
    cores: navigator.hardwareConcurrency ?? null,
    jsHeapMB: mem ? round(mem.usedJSHeapSize / 1048576, 1) : null,
  };
}

export function networkFacts() {
  const c = navigator.connection;
  return c ? { effectiveType: c.effectiveType ?? null, saveData: !!c.saveData } : { effectiveType: null, saveData: null };
}

export function round(n, digits = 1) {
  const f = 10 ** digits;
  return Math.round(n * f) / f;
}

export function clip(s, n) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) : s;
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// A fixed shader workload, timed: renderer strings can be masked ("Apple GPU") or
// say nothing about speed, so the same work in milliseconds tells a real GPU from
// a software renderer and places the device on one scale across engines.
// Result: milliseconds per pass of a 512x512 quad running 64 iterations per pixel.
const BENCH_FS = `precision highp float;
uniform float s;
void main() {
  vec2 p = gl_FragCoord.xy / 512.0;
  float a = s;
  for (int i = 0; i < 64; i++) { a = sin(a * 1.7 + p.x) * cos(a * 1.3 - p.y) + fract(a * 3.1); }
  gl_FragColor = vec4(a, p, 1.0);
}`;

export function gpuBench(doc = document, budgetMs = 1500) {
  const canvas = doc.createElement("canvas");
  canvas.width = canvas.height = 512;
  let gl = null;
  try {
    gl = canvas.getContext("webgl", { antialias: false, preserveDrawingBuffer: false });
  } catch {
    gl = null;
  }
  if (!gl) return null;
  const free = () => {
    try {
      gl.getExtension("WEBGL_lose_context")?.loseContext();
    } catch {
      // nothing to free
    }
  };
  try {
    const sh = (type, src) => {
      const x = gl.createShader(type);
      gl.shaderSource(x, src);
      gl.compileShader(x);
      return x;
    };
    const prog = gl.createProgram();
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, "attribute vec2 p; void main(){ gl_Position = vec4(p, 0., 1.); }"));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, BENCH_FS));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return free(), null;
    gl.useProgram(prog);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    const u = gl.getUniformLocation(prog, "s");
    const px = new Uint8Array(4);
    const run = (passes) => {
      const t0 = performance.now();
      for (let i = 0; i < passes; i++) {
        gl.uniform1f(u, i * 0.37);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      }
      gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px); // waits for the GPU
      return performance.now() - t0;
    };
    run(1); // compile and first use, not counted
    const start = performance.now();
    // calibrate: grow the pass count until one sample takes 20 ms, so coarse timers
    // (some engines round to 1 ms) cannot turn a fast GPU into zero
    let passes = 1;
    let total = run(passes);
    while (total < 20 && passes < 4096 && performance.now() - start < budgetMs) {
      passes *= 4;
      total = run(passes);
    }
    const samples = [total / passes];
    while (samples.length < 3 && performance.now() - start < budgetMs) samples.push(run(passes) / passes);
    free();
    samples.sort((a, b) => a - b);
    return samples.length ? round(samples[Math.floor(samples.length / 2)], 3) : null;
  } catch {
    free();
    return null;
  }
}
