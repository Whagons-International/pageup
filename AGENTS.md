# Sharing an HTML page

Use the `$pages` skill to create polished project summaries, progress reports, demos, and other shareable HTML artifacts. The underlying CLI is named **Pageup** and its executable command is `pageup`.

When a human needs to inspect or share a generated HTML artifact, upload it with:

```sh
pageup path/to/page.html
```

For a small multi-page experiment, pass a directory with `index.html` at its root:

```sh
pageup path/to/site
```

Site directories may contain up to 100 `.html` files in nested folders. Keep CSS and JavaScript inline and use URLs for images and other assets.

The command prints only the shareable URL on success. Use `pageup --json page.html` when a machine-readable response is preferable, or pipe content with `pageup -`.

To replace an existing page without changing its UUID, use:

```sh
pageup update <URL-or-UUID> path/to/page.html
pageup update <URL-or-UUID> path/to/site
```

The page's creator key or an admin key may update it. `pageup update <URL-or-UUID> -` accepts HTML from standard input.

# Sharing a file

To give a human or another agent a link to any other file, such as a screenshot, image, PDF, log, data export, archive, or recording, use:

```sh
pageup file path/to/screenshot.png
pageup file build/report.pdf logs/run.log
some-command 2>&1 | pageup file --name run.log -
```

A single non-HTML path also works as `pageup path/to/file`. Each file gets a public-but-unlisted URL at `/f/<uuid>/<name>`. Images, PDFs, media, text, and JSON open in the browser; other types download. Reference shared image URLs from HTML pages instead of embedding assets. `pageup update <file-URL> path` replaces a file at the same URL (`--name` renames it), and `pageup delete <file-URL>` removes it. Never share secrets, `.env` files, or unredacted logs.

Run `pageup doctor` if credentials or connectivity are in doubt. Never print, commit, or copy the private key from `~/.config/pageup/config.json`.

If Pageup is missing, install it from `https://pageup.whagons.com/install.sh` on macOS or Linux, or `https://pageup.whagons.com/install.ps1` on Windows. Run `pageup auth login` to authorize the device through the Whagons Google developer allowlist.
