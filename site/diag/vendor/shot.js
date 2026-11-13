// Canvas screenshot, downscaled to at most `maxWidth` CSS-independent pixels.
// A WebGL canvas without preserveDrawingBuffer is only readable right after it
// was drawn, so the copy is taken inside an animation frame; apps can instead
// pass `capture()` that renders and returns a canvas in one go.

export function largestCanvas(doc = document) {
  let best = null;
  let area = 0;
  for (const c of doc.querySelectorAll("canvas")) {
    if (c.closest?.("[data-diag-panel]")) continue;
    const a = c.width * c.height;
    if (a > area) {
      area = a;
      best = c;
    }
  }
  return best;
}

function isBlank(ctx, w, h) {
  // sample a 16x16 grid: a cleared WebGL buffer reads back as all zeros
  for (let y = 0; y < 16; y++)
    for (let x = 0; x < 16; x++) {
      const d = ctx.getImageData(Math.floor(((x + 0.5) * w) / 16), Math.floor(((y + 0.5) * h) / 16), 1, 1).data;
      if (d[0] || d[1] || d[2] || d[3]) return false;
    }
  return true;
}

function encode(canvas) {
  for (const [type, q] of [["image/webp", 0.82], ["image/jpeg", 0.85]]) {
    const url = canvas.toDataURL(type, q);
    if (url.startsWith(`data:${type}`)) return url;
  }
  return canvas.toDataURL("image/png");
}

export async function screenshot({ capture, canvas, maxWidth = 1280 } = {}) {
  let source = null;
  try {
    source = capture ? await capture() : canvas ? canvas() : largestCanvas();
  } catch (e) {
    return { image: null, reason: "capture failed: " + String(e?.message ?? e).slice(0, 120) };
  }
  if (!source) return { image: null, reason: "no canvas on the page" };
  if (typeof source === "string") return { image: source, reason: null, width: null, height: null, blank: false };
  return new Promise((resolve) => {
    requestAnimationFrame(() => {
      try {
        const scale = Math.min(1, maxWidth / source.width);
        const w = Math.max(1, Math.round(source.width * scale));
        const h = Math.max(1, Math.round(source.height * scale));
        const out = document.createElement("canvas");
        out.width = w;
        out.height = h;
        const ctx = out.getContext("2d", { willReadFrequently: true });
        ctx.drawImage(source, 0, 0, w, h);
        const blank = isBlank(ctx, w, h);
        resolve({ image: encode(out), reason: blank ? "canvas read back empty" : null, width: w, height: h, blank });
      } catch (e) {
        // a tainted canvas (cross-origin texture without CORS) cannot be read
        resolve({ image: null, reason: "canvas not readable: " + String(e?.name ?? e).slice(0, 60) });
      }
    });
  });
}
