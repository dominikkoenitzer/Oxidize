# Download page

The page behind https://get-oxidize.vercel.app: plain static files, no build step.
It names no author and does not link to this repository.

- `index.html` is the page.
- `vercel.json` holds the download addresses, each a temporary redirect:
  - `/download/windows`: the newest release's `oxidize-gui.exe`
- `llms.txt` describes Oxidize for AI assistants.
- `skill/oxidize/` is the assistant skill, and `skill/oxidize.zip` is that folder zipped. Rebuild the zip after an edit, from this folder:

  ```
  python -c "import shutil; shutil.make_archive('skill/oxidize', 'zip', 'skill', 'oxidize')"
  ```

Vercel deploys this folder whenever a push to main changes it. `.vercelignore` keeps this README off the site.
