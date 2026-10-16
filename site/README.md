# Download page

The page behind https://get-oxidize.vercel.app: static files, no build step on the server.
It names no author and does not link to this repository.

- `page.json` holds every word on the page and which screenshots it shows.
- `build.py` turns `page.json` into `index.html`. The same `build.py` sits in every app's
  `site/` folder, so all the download pages share one design. After an edit:

  ```
  python build.py
  ```

- `img/` holds real screenshots of the app as WebP, `-light` and `-dark` where the app has both
  looks. Never put a mock-up or an edited screenshot there.
- `jakarta.woff2` is the Plus Jakarta Sans typeface, served from the page itself;
  `jakarta-OFL.txt` is its licence.
- `og.png` is the 1200x630 card a chat app shows when someone shares the page. It is a picture of
  the page's own hero: rebuild it when the hero screenshot changes.
- `vercel.json` holds the download addresses, each a temporary redirect:
  - `/download/windows`
  - `/download/cli`
  - `/download/zip`
  - `/download/windows.sha256`
  - `/download/cli.sha256`
  - `/download/zip.sha256`
- `llms.txt` describes the app for AI assistants.
- `skill/oxidize/` is the assistant skill, and `skill/oxidize.zip` is that folder zipped. Rebuild the zip
  after an edit, from this folder:

  ```
  python -c "import shutil; shutil.make_archive('skill/oxidize', 'zip', 'skill', 'oxidize')"
  ```

Vercel deploys this folder whenever a push to main changes it. `.vercelignore` keeps this README,
`build.py` and `page.json` off the site.
