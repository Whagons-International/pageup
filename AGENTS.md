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

Run `pageup doctor` if credentials or connectivity are in doubt. Never print, commit, or copy the private key from `~/.config/pageup/config.json`.

If Pageup is missing, install it from `https://pageup.whagons.com/install.sh` on macOS or Linux, or `https://pageup.whagons.com/install.ps1` on Windows. Run `pageup auth login` to authorize the device through the Whagons Google developer allowlist.
