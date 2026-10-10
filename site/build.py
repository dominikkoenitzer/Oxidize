"""Builds index.html for this download page from page.json.

The same file sits in every app's site/ folder, so all pages share one design.
Run it from anywhere: python build.py
"""
import html
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# Every app, for the "All apps" grid. The page leaves out its own app.
APPS = [
    ("inkling", "Inkling", "https://get-inkling.vercel.app/", "#4155b9", "#a4b1f0",
     "Notes, to-dos and flashcards in one calm place.", "Windows, macOS, Linux"),
    ("oxidize", "Oxidize", "https://get-oxidize.vercel.app/", "#a04e22", "#f7b27a",
     "Uninstall programs and clear out what they leave behind.", "Windows"),
    ("mochi", "Mochi", "https://get-mochi.vercel.app/", "#ae3274", "#ffbbdf",
     "Every open window side by side, moved from the keyboard.", "Windows"),
    ("remnants", "Remnants", "https://get-remnants.vercel.app/", "#2563eb", "#7fb2fb",
     "A code editor with every AI feature taken out.", "Windows, macOS, Linux"),
    ("jester", "Jester", "https://get-jester.vercel.app/", "#5e2a82", "#c397e3",
     "A fast notepad for Windows, in purple and gold.", "Windows"),
    ("flow", "Flow", "https://get-flow-app.vercel.app/", "#2f5ebc", "#a9c5fc",
     "Record a task once, and it repeats it for you.", "Windows"),
    ("daifuku", "Daifuku", "https://get-daifuku.vercel.app/", "#225ebf", "#89b4fa",
     "A grid of AI agent terminals that shows what each one is doing.", "Windows"),
]

CSS = r"""
@font-face {
  font-family: "Jakarta";
  src: url("jakarta.woff2") format("woff2");
  font-weight: 200 800;
  font-display: swap;
}
:root {
  --bg: #f7f6f3;
  --card: #ffffff;
  --line: rgb(24 26 34 / 0.09);
  --text: #16171c;
  --muted: #5d606b;
  --code-bg: #16171c;
  --code-text: #e8e8ee;
  --shadow-sm: 0 1px 2px rgb(16 18 30 / 0.06), 0 6px 20px rgb(16 18 30 / 0.06);
  --shadow-lg: 0 2px 6px rgb(16 18 30 / 0.06), 0 30px 80px rgb(16 18 30 / 0.16);
  --tile-shadow: 22px 22px 54px rgb(40 48 110 / 0.16), -16px -16px 44px rgb(255 255 255 / 0.9);
  --hang: clamp(4rem, 10vw, 9rem);
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111215;
    --card: #1a1b20;
    --line: rgb(236 236 240 / 0.09);
    --text: #f0f0f3;
    --muted: #a5a8b2;
    --code-bg: #0b0c0e;
    --code-text: #e8e8ee;
    --shadow-sm: 0 1px 2px rgb(0 0 0 / 0.5), 0 6px 20px rgb(0 0 0 / 0.35);
    --shadow-lg: 0 2px 6px rgb(0 0 0 / 0.5), 0 30px 80px rgb(0 0 0 / 0.6);
    --tile-shadow: 18px 18px 46px rgb(0 0 0 / 0.45), -12px -12px 36px rgb(255 255 255 / 0.03);
  }
}
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 17px/1.6 "Jakarta", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
  overflow-x: clip;
}
a { color: var(--accent-ink); text-underline-offset: 0.18em; }
a:focus-visible, .btn:focus-visible, summary:focus-visible { outline: 3px solid var(--accent-ink); outline-offset: 3px; border-radius: 0.6rem; }
img { display: block; max-width: 100%; height: auto; }
picture { display: contents; }
kbd { font: inherit; font-weight: 700; color: var(--text); }
code { font: 0.92em/1.5 ui-monospace, "Cascadia Mono", Consolas, monospace; }
.wrap { position: relative; max-width: 78rem; margin: 0 auto; padding: 0 1.5rem; }
section[id] { scroll-margin-top: 1.5rem; }

.btn {
  display: inline-flex;
  align-items: center;
  padding: 1.05rem 1.6rem;
  border-radius: 0.95rem;
  background: var(--accent);
  color: #fff;
  font-weight: 650;
  font-size: 1.05rem;
  text-decoration: none;
  box-shadow: 0 1px 2px rgb(0 0 0 / 0.12), 0 8px 24px color-mix(in srgb, var(--accent) 30%, transparent);
  transition: background-color 0.15s ease, transform 0.15s ease;
}
.btn:hover { background: var(--accent-hover); transform: translateY(-1px); }
.btn.quiet {
  background: var(--card);
  color: var(--text);
  box-shadow: var(--shadow-sm);
  border: 1px solid var(--line);
  padding: 0.6rem 1rem;
  font-size: 0.92rem;
  border-radius: 0.75rem;
}
.btn.quiet:hover { border-color: var(--accent-ink); }

.band { position: relative; background: var(--band); padding-bottom: clamp(3rem, 6vw, 5rem); }
.tiles-clip { position: absolute; inset: 0; overflow: hidden; pointer-events: none; }
.tiles {
  position: absolute;
  inset: -6rem -10rem auto auto;
  width: 64rem;
  display: grid;
  grid-template-columns: repeat(3, 17rem);
  grid-auto-rows: 17rem;
  gap: 3.5rem;
  -webkit-mask-image: radial-gradient(closest-side at 60% 45%, #000 55%, transparent 100%);
  mask-image: radial-gradient(closest-side at 60% 45%, #000 55%, transparent 100%);
}
.tiles i { border-radius: 4.25rem; background: var(--tile); box-shadow: var(--tile-shadow); }
nav.top { position: relative; display: flex; align-items: center; justify-content: space-between; padding-block: 1.5rem; }
.word { font-weight: 750; font-size: 1.15rem; letter-spacing: -0.02em; color: var(--text); text-decoration: none; }
.links { display: flex; align-items: center; gap: 1.6rem; }
.links a:not(.btn) { color: var(--muted); text-decoration: none; font-size: 0.95rem; font-weight: 550; }
.links a:not(.btn):hover { color: var(--text); }
.hero {
  position: relative;
  display: grid;
  grid-template-columns: minmax(0, 5fr) minmax(0, 7fr);
  gap: clamp(2rem, 4vw, 4rem);
  align-items: center;
  padding-top: clamp(2.5rem, 8vh, 5.5rem);
}
h1 { margin: 0; font-size: clamp(3.5rem, 9vw, 7.75rem); line-height: 0.92; letter-spacing: -0.055em; font-weight: 780; }
.lede { margin: 1.5rem 0 0; max-width: 27rem; font-size: clamp(1.15rem, 1.7vw, 1.3rem); line-height: 1.5; }
.get { margin-top: 2.25rem; }
.small { margin: 1rem 0 0; font-size: 0.93rem; color: var(--muted); line-height: 1.5; }
.small + .small { margin-top: 0.3rem; }
.away { color: var(--text); }
.window {
  position: relative;
  z-index: 2;
  margin: 0;
  transform: translateY(var(--hang));
  border-radius: 1.25rem;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
  border: 1px solid var(--line);
  background: var(--card);
}
.hero-shot { align-self: start; margin-top: clamp(0rem, 2vw, 1.5rem); }
.window.portrait { width: min(100%, 25rem); margin-left: auto; margin-right: auto; }
.stage.portrait { aspect-ratio: 1 / 1.05; padding: clamp(1.5rem, 4vw, 3rem); display: flex; justify-content: center; }
.stage.portrait .main { height: 100%; width: auto; aspect-ratio: var(--ar); border-radius: 1rem; }

.features { padding-top: calc(var(--hang) + clamp(4rem, 8vw, 7rem)); }
.feature {
  display: grid;
  grid-template-columns: minmax(0, 5fr) minmax(0, 7fr);
  gap: clamp(2rem, 5vw, 5rem);
  align-items: center;
  margin-bottom: clamp(5rem, 11vw, 8.5rem);
}
.feature.flip { grid-template-columns: minmax(0, 7fr) minmax(0, 5fr); }
.feature.flip .text { order: 2; }
.label { margin: 0 0 0.75rem; font-weight: 650; font-size: 0.92rem; color: var(--accent-ink); }
h2 { margin: 0; font-size: clamp(2rem, 3.6vw, 3rem); line-height: 1.05; letter-spacing: -0.04em; font-weight: 750; }
.text p:not(.label), .lead { margin: 1.1rem 0 0; max-width: 28rem; color: var(--muted); font-size: 1.05rem; }
.stage {
  position: relative;
  border-radius: 1.75rem;
  background: var(--stage);
  padding: clamp(1.5rem, 4vw, 3rem) 0 0 clamp(1.5rem, 4vw, 3rem);
  aspect-ratio: 5 / 4;
}
.stage .main {
  height: 100%;
  border-radius: 1rem 0 1.75rem 0;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
  border: 1px solid var(--line);
  background: var(--card);
}
.stage .main img { width: 100%; height: 100%; object-fit: cover; object-position: var(--pos, 0 0); transform: scale(var(--zoom, 1)); transform-origin: var(--pos, 0 0); }
.stage .detail {
  position: absolute;
  width: 46%;
  left: -6%;
  bottom: 9%;
  border-radius: 1rem;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
  border: 1px solid var(--line);
  background: var(--card);
}
.feature.flip .stage .detail { left: auto; right: -6%; }
.stage .detail img { width: 100%; height: auto; }

.pair { position: relative; padding: 0 0 clamp(3rem, 8vw, 5rem); margin-bottom: clamp(5rem, 11vw, 8rem); }
.pair .head { max-width: 40rem; margin-bottom: clamp(2rem, 5vw, 3.5rem); }
.pair .shots { position: relative; height: clamp(16rem, 42vw, 36rem); }
.pair .shot {
  position: absolute;
  width: 68%;
  border-radius: 1.1rem;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
  border: 1px solid var(--line);
  background: var(--card);
}
.pair .shot.one { left: 0; top: 0; }
.pair .shot.two { right: 0; top: 18%; }

.assistant {
  display: grid;
  grid-template-columns: minmax(0, 5fr) minmax(0, 7fr);
  gap: clamp(2rem, 5vw, 5rem);
  align-items: center;
  margin-bottom: clamp(5rem, 11vw, 8rem);
}
.codecard {
  border-radius: 1.4rem;
  background: var(--code-bg);
  color: var(--code-text);
  box-shadow: var(--shadow-lg);
  padding: 1.5rem 1.6rem;
  overflow-x: auto;
}
.codecard .cap { margin: 0 0 0.8rem; font-size: 0.82rem; color: #9a9db0; font-weight: 600; }
.codecard pre { margin: 0; white-space: pre; }
.codecard code { font-size: 0.9rem; color: var(--code-text); }

.grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1.25rem; margin-bottom: clamp(5rem, 11vw, 8rem); }
.grid3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1.25rem; margin-bottom: clamp(5rem, 11vw, 8rem); }
.card { border-radius: 1.4rem; background: var(--card); border: 1px solid var(--line); box-shadow: var(--shadow-sm); padding: 1.75rem; }
.card .num { font-size: 0.85rem; font-weight: 700; color: var(--accent-ink); }
.card h3 { margin: 0.5rem 0 0; font-size: 1.3rem; letter-spacing: -0.02em; font-weight: 700; }
.card p, .card ul, .card ol { margin: 0.6rem 0 0; color: var(--muted); font-size: 0.98rem; }
.card ul, .card ol { padding-left: 1.15rem; }
.card li { margin: 0.3rem 0; }
.card li::marker { color: var(--accent-ink); }
.sectionhead { margin-bottom: 2rem; }
.sectionhead h2 { font-size: clamp(1.8rem, 3vw, 2.4rem); }
.sectionhead p { margin: 0.6rem 0 0; color: var(--muted); }

.keys { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 2.5rem; margin: 0 0 clamp(5rem, 11vw, 8rem); padding: 0; list-style: none; }
.keys li { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.95rem 0; border-top: 1px solid var(--line); }
.keys li span { color: var(--muted); }
.keys kbd { display: inline-flex; gap: 0.3rem; flex-wrap: wrap; justify-content: flex-end; }
.keys kbd kbd {
  font-size: 0.85rem;
  font-weight: 650;
  padding: 0.25rem 0.55rem;
  border-radius: 0.5rem;
  background: var(--card);
  border: 1px solid var(--line);
  box-shadow: 0 1px 0 var(--line);
}

.faq { margin: 0 0 clamp(5rem, 11vw, 8rem); border-top: 1px solid var(--line); }
.faq details { border-bottom: 1px solid var(--line); }
.faq summary {
  list-style: none;
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: 1.2rem 0;
  font-weight: 650;
  font-size: 1.08rem;
}
.faq summary::-webkit-details-marker { display: none; }
.faq summary::after { content: "+"; color: var(--accent-ink); font-weight: 500; font-size: 1.35rem; line-height: 1; }
.faq details[open] summary::after { content: "\2212"; }
.faq .answer { margin: -0.3rem 0 1.3rem; max-width: 46rem; color: var(--muted); }
.faq .answer p { margin: 0 0 0.6rem; }

.apps-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1.25rem; margin: 0; padding: 0; list-style: none; }
.app {
  display: flex;
  flex-direction: column;
  height: 100%;
  border-radius: 1.4rem;
  overflow: hidden;
  background: var(--card);
  border: 1px solid var(--line);
  box-shadow: var(--shadow-sm);
  color: inherit;
  text-decoration: none;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
  --ink: var(--c-ink);
}
@media (prefers-color-scheme: dark) { .app { --ink: var(--c-ink-dark); } }
.app:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
.art { height: 9.5rem; padding: 1.25rem 1.4rem; display: flex; align-items: flex-end; background: var(--c); color: #fff; font-size: 2.1rem; font-weight: 760; letter-spacing: -0.04em; }
.app .body { flex: 1; display: flex; flex-direction: column; padding: 1.15rem 1.4rem 1.3rem; }
.app .line { margin: 0; color: var(--muted); font-size: 0.97rem; line-height: 1.45; flex: 1; }
.app .row { display: flex; align-items: center; justify-content: space-between; margin-top: 1.1rem; }
.app .os { font-size: 0.85rem; color: var(--muted); }
.pill { font-size: 0.88rem; font-weight: 650; color: var(--ink); background: color-mix(in srgb, var(--ink) 14%, transparent); padding: 0.45rem 0.95rem; border-radius: 999px; }

.closing {
  margin: clamp(5rem, 11vw, 8rem) 0 2.5rem;
  border-radius: 2rem;
  background: var(--band);
  padding: clamp(2.5rem, 6vw, 4.5rem);
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 2rem;
  align-items: center;
}
.closing h2 { font-size: clamp(2rem, 4vw, 3.25rem); }
.closing p { margin: 0.6rem 0 0; color: var(--muted); }
footer { padding: 0 0 3rem; font-size: 0.92rem; color: var(--muted); }
footer p { margin: 0.3rem 0; }

@media (max-width: 900px) {
  :root { --hang: clamp(3rem, 14vw, 6rem); }
  .tiles { inset: auto -12rem -6rem auto; opacity: 0.55; }
  .hero, .feature, .assistant { grid-template-columns: minmax(0, 1fr); }
  .feature.flip { grid-template-columns: minmax(0, 1fr); }
  .feature.flip .text { order: 0; }
  .grid2, .grid3, .apps-grid, .keys, .closing { grid-template-columns: minmax(0, 1fr); }
  .links a:not(.btn) { display: none; }
  .stage .detail { left: auto; right: 4%; bottom: -8%; width: 52%; }
  .feature.flip .stage .detail { right: 4%; }
  .feature { margin-bottom: clamp(6rem, 18vw, 8rem); }
  .pair .shot { width: 80%; }
}
@media (min-width: 901px) and (max-width: 1180px) {
  .apps-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  .btn, .app { transition: none; }
  .btn:hover, .app:hover { transform: none; }
}
"""

SCRIPT = r"""
(function () {
  var d = document;
  var names = JSON.parse(d.body.getAttribute("data-platforms"));
  var keys = Object.keys(names);
  var uad = navigator.userAgentData;
  var plat = ((uad && uad.platform) || navigator.platform || "").toLowerCase();
  var ua = navigator.userAgent.toLowerCase();
  var os = "";
  if ((uad && uad.mobile) || /android|iphone|ipad|ipod/.test(ua) || (/mac/.test(plat) && navigator.maxTouchPoints > 1)) os = "mobile";
  else if (/win/.test(plat) || /windows/.test(ua)) os = "windows";
  else if (/mac/.test(plat) || /mac os x/.test(ua)) os = "mac";
  else if (/linux/.test(plat) || /linux|x11/.test(ua)) os = "linux";

  function render(key) {
    d.querySelectorAll("[data-primary]").forEach(function (a) {
      a.href = "/download/" + key;
      a.textContent = "Download for " + names[key];
    });
    var rest = keys.filter(function (k) { return k !== key; });
    var others = d.getElementById("others");
    if (!others) return;
    if (!rest.length) { others.hidden = true; return; }
    others.textContent = "Also for ";
    rest.forEach(function (k, i) {
      if (i) others.append(i === rest.length - 1 ? " and " : ", ");
      var a = d.createElement("a");
      a.href = "/download/" + k;
      a.textContent = names[k];
      others.append(a);
    });
    others.append(".");
  }

  if (names[os]) render(os);
  else d.getElementById("away").hidden = false;

  if (os === "windows" && names["windows-arm"] && uad && uad.getHighEntropyValues) {
    uad.getHighEntropyValues(["architecture"]).then(function (v) {
      if (v.architecture === "arm") render("windows-arm");
    }).catch(function () {});
  }
})();
"""


def esc(s):
    return html.escape(s, quote=True)


def picture(img, alt=None, cls=""):
    """img: {"name": ..., "w": ..., "h": ..., "dark": bool}. Files are img/<name>-light.webp and -dark.webp."""
    name, w, h = img["name"], img["w"], img["h"]
    alt = esc(alt if alt is not None else img.get("alt", ""))
    light = f"img/{name}-light.webp" if img.get("dark", True) else f"img/{name}.webp"
    source = (f'<source srcset="img/{name}-dark.webp" media="(prefers-color-scheme: dark)">'
              if img.get("dark", True) else "")
    c = f' class="{cls}"' if cls else ""
    return f'<picture>{source}<img src="{light}" width="{w}" height="{h}" alt="{alt}" loading="lazy" decoding="async"{c}></picture>'


def build(page):
    slug, name = page["slug"], page["name"]
    a = page["colours"]
    parts = []
    w = parts.append
    w("<!doctype html>")
    w('<html lang="en">')
    w("<head>")
    w('<meta charset="utf-8">')
    w('<meta name="viewport" content="width=device-width, initial-scale=1">')
    w(f"<title>{esc(name)}</title>")
    w(f'<meta name="description" content="{esc(page["description"])}">')
    w(f'<meta property="og:title" content="{esc(name)}">')
    w(f'<meta property="og:description" content="{esc(page["description"])}">')
    w('<meta name="color-scheme" content="light dark">')
    w('<link rel="icon" href="data:,">')
    w('<link rel="preload" href="jakarta.woff2" as="font" type="font/woff2" crossorigin>')
    w("<style>")
    w("/* app colours */")
    w(":root {")
    for k, v in a["light"].items():
        w(f"  --{k}: {v};")
    w("}")
    w("@media (prefers-color-scheme: dark) {")
    w("  :root {")
    for k, v in a["dark"].items():
        w(f"    --{k}: {v};")
    w("  }")
    w("}")
    w("/* shared */" + CSS)
    w("</style>")
    w("</head>")
    w(f"<body data-platforms='{esc(json.dumps(page['platforms']))}'>")

    # hero
    first = next(iter(page["platforms"]))
    w('<header class="band">')
    w('<div class="tiles-clip" aria-hidden="true"><div class="tiles">' + "<i></i>" * 9 + "</div></div>")
    w('<div class="wrap">')
    w('<nav class="top" aria-label="Page">')
    w(f'<a class="word" href="#">{esc(name)}</a>')
    w('<div class="links">')
    w('<a href="#features">Features</a>')
    w('<a href="#new">What\'s new</a>')
    w('<a href="#faq">Questions</a>')
    w('<a href="#apps">All apps</a>')
    w(f'<a class="btn quiet" href="/download/{first}">Download</a>')
    w("</div>")
    w("</nav>")
    w('<div class="hero">')
    w("<div>")
    w(f"<h1>{esc(name)}</h1>")
    w(f'<p class="lede">{page["hero"]["lede"]}</p>')
    w('<div class="get">')
    w(f'<a class="btn" id="primary" data-primary href="/download/{first}">Download for {esc(page["platforms"][first])}</a>')
    if page["hero"].get("also"):
        w(f'<p class="small" id="others">{page["hero"]["also"]}</p>')
    for line in page["hero"].get("notes", []):
        w(f'<p class="small">{line}</p>')
    w(f'<p class="small away" id="away" hidden>{page["hero"]["away"]}</p>')
    w("</div>")
    w("</div>")
    w('<div class="hero-shot">')
    hero_pic = picture(page["hero"]["image"]).replace(' loading="lazy"', ' fetchpriority="high"')
    hero_cls = "window portrait" if page["hero"]["image"].get("portrait") else "window"
    w(f'<figure class="{hero_cls}">{hero_pic}</figure>')
    w("</div>")
    w("</div>")
    w("</div>")
    w("</header>")

    w('<main class="wrap">')
    # features
    w('<section class="features" id="features" aria-label="Features">')
    for i, f in enumerate(page["features"]):
        flip = " flip" if i % 2 else ""
        w(f'<div class="feature{flip}">')
        w('<div class="text">')
        w(f'<p class="label">{esc(f["label"])}</p>')
        w(f'<h2>{f["title"]}</h2>')
        for p in f["body"]:
            w(f"<p>{p}</p>")
        w("</div>")
        m = f["main"]
        w('<div class="stage portrait">' if m.get("portrait") else '<div class="stage">')
        style = f' style="--pos: {m.get("pos", "0 0")}; --zoom: {m.get("zoom", 1)}; --ar: {m["w"]} / {m["h"]}"'
        w(f'<div class="main"{style}>{picture(m)}</div>')
        if f.get("detail"):
            d = f["detail"]
            dstyle = f' style="{d["style"]}"' if d.get("style") else ""
            w(f'<div class="detail"{dstyle}>{picture(d, alt="")}</div>')
        w("</div>")
        w("</div>")
    w("</section>")

    # light and dark
    if page.get("pair"):
        p = page["pair"]
        w('<section class="pair" aria-labelledby="pair-h">')
        w('<div class="head">')
        w(f'<p class="label">{esc(p["label"])}</p>')
        w(f'<h2 id="pair-h">{p["title"]}</h2>')
        for t in p["body"]:
            w(f'<p class="lead">{t}</p>')
        w("</div>")
        w('<div class="shots">')
        w(f'<div class="shot one">{picture(p["one"])}</div>')
        w(f'<div class="shot two">{picture(p["two"])}</div>')
        w("</div>")
        w("</section>")

    # assistant
    if page.get("assistant"):
        s = page["assistant"]
        w('<section class="assistant" aria-labelledby="ai-h">')
        w('<div class="text">')
        w(f'<p class="label">{esc(s["label"])}</p>')
        w(f'<h2 id="ai-h">{s["title"]}</h2>')
        for t in s["body"]:
            w(f"<p>{t}</p>")
        w("</div>")
        w('<div class="codecard">')
        w(f'<p class="cap">{esc(s["caption"])}</p>')
        w(f'<pre><code>{esc(s["code"])}</code></pre>')
        w("</div>")
        w("</section>")

    # what's new, requirements, privacy, data
    w('<section id="new" aria-label="Details">')
    w('<div class="grid2">')
    n = page["new"]
    w('<div class="card">')
    w(f'<div class="num">{esc(n.get("label") or "Version " + n["version"])}</div>')
    w("<h3>What's new</h3>")
    w("<ul>" + "".join(f"<li>{x}</li>" for x in n["items"]) + "</ul>")
    w("</div>")
    w('<div class="card">')
    w('<div class="num">Requirements</div>')
    w("<h3>What you need</h3>")
    w("<ul>" + "".join(f"<li>{x}</li>" for x in page["requirements"]) + "</ul>")
    w("</div>")
    w('<div class="card">')
    w('<div class="num">Privacy</div>')
    w(f'<h3>{page["privacy"]["title"]}</h3>')
    for t in page["privacy"]["body"]:
        w(f"<p>{t}</p>")
    w("</div>")
    w('<div class="card">')
    w('<div class="num">Your data</div>')
    w(f'<h3>{page["data"]["title"]}</h3>')
    for t in page["data"]["body"]:
        w(f"<p>{t}</p>")
    w("</div>")
    w("</div>")
    w("</section>")

    # shortcuts
    if page.get("keys"):
        w('<section aria-labelledby="keys-h">')
        w('<div class="sectionhead">')
        w('<h2 id="keys-h">Keyboard</h2>')
        if page.get("keys_note"):
            w(f"<p>{page['keys_note']}</p>")
        w("</div>")
        w('<ul class="keys">')
        for combo, what in page["keys"]:
            chips = "".join(f"<kbd>{esc(k)}</kbd>" for k in combo.split(" "))
            w(f"<li><span>{what}</span><kbd>{chips}</kbd></li>")
        w("</ul>")
        w("</section>")

    # start, update, remove
    w('<section aria-label="Install, update and remove">')
    w('<div class="grid3">')
    for i, b in enumerate(page["basics"], 1):
        w('<div class="card">')
        w(f'<div class="num">0{i}</div>')
        w(f'<h3>{b["title"]}</h3>')
        if b.get("steps"):
            w("<ol>" + "".join(f"<li>{x}</li>" for x in b["steps"]) + "</ol>")
        for t in b.get("body", []):
            w(f"<p>{t}</p>")
        w("</div>")
    w("</div>")
    w("</section>")

    # faq
    w('<section id="faq" aria-labelledby="faq-h">')
    w('<div class="sectionhead"><h2 id="faq-h">Questions</h2></div>')
    w('<div class="faq">')
    for q in page["faq"]:
        w("<details>")
        w(f'<summary>{q["q"]}</summary>')
        w('<div class="answer">' + "".join(f"<p>{x}</p>" for x in q["a"]) + "</div>")
        w("</details>")
    w("</div>")
    w("</section>")

    # all apps
    w('<section class="apps" id="apps" aria-labelledby="apps-h">')
    w('<div class="sectionhead">')
    w('<h2 id="apps-h">All apps</h2>')
    w("<p>Other apps, all free.</p>")
    w("</div>")
    w('<ul class="apps-grid">')
    for s, title, url, c, cd, line, os_ in APPS:
        if s == slug:
            continue
        w(f'<li><a class="app" href="{url}" style="--c:{c};--c-ink:{c};--c-ink-dark:{cd}">'
          f'<div class="art">{esc(title)}</div><div class="body"><p class="line">{esc(line)}</p>'
          f'<div class="row"><span class="os">{esc(os_)}</span><span class="pill">Get it</span></div></div></a></li>')
    w("</ul>")
    w("</section>")

    # closing
    c = page["closing"]
    w('<section class="closing" aria-label="Download">')
    w("<div>")
    w(f'<h2>{c["title"]}</h2>')
    w(f'<p>{c["sub"]}</p>')
    w("</div>")
    w(f'<a class="btn" data-primary href="/download/{first}">Download for {esc(page["platforms"][first])}</a>')
    w("</section>")
    w("<footer>")
    for line in page.get("footer", []):
        w(f"<p>{line}</p>")
    w("</footer>")
    w("</main>")
    w("<script>" + SCRIPT + "</script>")
    w("</body>")
    w("</html>")
    return "\n".join(parts) + "\n"


if __name__ == "__main__":
    with open(os.path.join(HERE, "page.json"), encoding="utf-8") as fh:
        page = json.load(fh)
    out = build(page)
    with open(os.path.join(HERE, "index.html"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(out)
    print("wrote", os.path.join(HERE, "index.html"), len(out), "bytes")
