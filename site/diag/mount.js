// The diagnostic panel on /diag: it measures this browser for ten seconds and shows the result.
// No address for reports is set up for this site, so Send says so instead of posting anywhere.

import { installCapture } from "/diag/vendor/capture.js";
import { installVitals } from "/diag/vendor/measure.js";
import { mountPanel } from "/diag/vendor/panel.js";

installCapture();
installVitals();

const app = document.querySelector('meta[name="diag-app"]').content;
const reopen = document.getElementById("reopen");
const NO_ADDRESS = "No address for reports is set up on this site, so nothing can be sent. The details above stay on your device.";

const quality = () => ({
  motion: matchMedia("(prefers-reduced-motion: reduce)").matches ? "reduced" : "full",
  theme: matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
});

// A click on Send is taken on the panel's shadow root before the panel's own handler sees it.
function holdSend() {
  const root = document.querySelector("[data-diag-panel]")?.shadowRoot;
  root?.addEventListener(
    "click",
    (event) => {
      const send = event.target?.closest?.("button.primary");
      if (!send) return;
      event.stopImmediatePropagation();
      event.preventDefault();
      const status = send.closest("section")?.querySelector('p[role="status"]');
      if (status) status.textContent = NO_ADDRESS;
      // Safari does not focus a clicked button, and the panel closes on Escape only with focus inside it.
      send.focus();
    },
    true,
  );
}

function open() {
  reopen.hidden = true;
  mountPanel({
    app,
    release: "site",
    lang: "en",
    quality,
    onClose: () => {
      reopen.hidden = false;
      reopen.focus();
    },
  });
  holdSend();
}

reopen.addEventListener("click", open);
// The panel waits a moment so it measures the page settled, as visitors see it.
const start = () => setTimeout(open, 1500);
if (document.readyState === "complete") start();
else addEventListener("load", start, { once: true });
