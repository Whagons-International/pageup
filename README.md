# Pageup for Whagons

Pageup turns a local HTML file or small HTML-only directory into an unlisted, shareable URL with one command, and shares any other file the same way:

```console
$ pageup-whagons report.html
https://pageup.whagons.com/019c...

$ pageup-whagons ./experiment
https://pageup.whagons.com/019d.../

$ pageup-whagons file screenshot.png build.log
https://pageup.whagons.com/f/019e.../screenshot.png
https://pageup.whagons.com/f/019e.../build.log
```

Viewing pages is public so links can be shared. Creating and updating pages requires a revocable Ed25519 device key. Teammates authorize a device by signing in with a Google account on the Whagons developer allowlist. The Google token is checked by Gonvex and is not stored by Pageup.

## Install

macOS or Linux:

```sh
curl -fsSL https://pageup.whagons.com/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://pageup.whagons.com/install.ps1 | iex
```

Authorize the device with your Whagons developer Google account:

```sh
pageup-whagons auth login
pageup-whagons doctor
```

Use `pageup-whagons auth login --no-open` on a headless machine. It prints `https://pageup.whagons.com/auth` and a short device code; open that address elsewhere, enter the code, and leave the remote command running until approval completes. Pageup creates one upload-only key for the device. Removing the email from the Whagons developer allowlist prevents new device authorization; existing device keys can be revoked by a Pageup admin.

Every Pageup CLI binary also contains the complete `$pages` agent skill. Install it into the detected Codex or `~/.agents` skill directory with:

```sh
pageup-whagons skill install
```

Use `pageup-whagons skill show` to inspect the embedded instructions, `--harness project` to install under `./.agents/skills`, or `--target DIR` for another agent harness. Existing skill files are preserved unless `--force` is supplied.

The manual pairing commands remain available for the bootstrap administrator:

```sh
PAGEUP_CONFIG=~/.config/pageup-whagons-admin.json pageup-whagons init --endpoint https://pageup.whagons.com --name "Pageup admin"
```

The command prints a public key and an approval command. Run that approval command on a computer which already has an admin credential, then verify the new computer:

```sh
pageup-whagons doctor
pageup-whagons example.html
```

This manual flow is not needed for normal team onboarding. It never moves a private key between computers. Use `pageup-whagons keys list` and `pageup-whagons keys revoke KEY_ID` from the bootstrap admin identity to audit or revoke devices.

## CLI

```text
pageup-whagons file.html                     upload a file; print its URL
pageup-whagons ./site                        upload an HTML-only directory
pageup-whagons -                             upload HTML from stdin
pageup-whagons --json file.html              return id, URL, and revision state as JSON
pageup-whagons --open file.html              upload and open in the default browser
pageup-whagons update URL file.html          update HTML without changing the URL
pageup-whagons update URL ./site             update or convert to a multi-page site
pageup-whagons update UUID -                 update by id with HTML from stdin
pageup-whagons photo.png                     share a non-HTML file; print its URL
pageup-whagons file a.pdf b.log              share several files, one URL per line
pageup-whagons file --name out.log -         share stdin under a file name
pageup-whagons update FILE_URL new.pdf       replace a file without changing its URL
pageup-whagons update --name v2.pdf URL f    replace and rename a file
pageup-whagons delete FILE_URL               delete a shared file
pageup-whagons auth login                    authorize this device with Google
pageup-whagons doctor                        test connectivity and authentication
pageup-whagons whoami                        show the active key
pageup-whagons public-key                    print this device's public key
pageup-whagons skill show                    print the embedded Pages skill
pageup-whagons skill install                 install Pages into an agent harness
pageup-whagons keys add --name NAME PUBKEY   authorize another device
pageup-whagons keys list                     list authorized devices
pageup-whagons keys revoke KEY_ID            revoke a device
```

For a multi-page site, pass a directory containing `index.html` at its root. Pageup recursively preserves up to 100 `.html` files, so links such as `href="about.html"` and `href="docs/"` work as expected. A nested `docs/index.html` is served at the directory-style URL `/docs/`. Directories may contain only HTML: keep CSS and JavaScript inline and use remote URLs for images, fonts, and other assets. The combined uncompressed HTML remains subject to the 5 MiB limit.

## File sharing

Any file that is not HTML can be shared: screenshots, images, PDFs, logs, data exports, archives, and recordings. A single non-HTML path is shared automatically, while `pageup-whagons file` accepts several paths or `-` for standard input with `--name`. Files without an extension are published as pages only when their content looks like HTML.

Shared files live at `/f/<uuid>/<name>`. The UUID identifies the file; a missing or outdated name redirects to the current one. Images, PDFs, audio, video, plain text, Markdown, CSV, and JSON are served inline, and every other type, including HTML and SVG, is served as an attachment. `?download` forces an attachment. Responses support Range requests, so media can seek, and they use `Cache-Control: no-cache` with a SHA-256 ETag, so updates appear immediately while unchanged files revalidate cheaply. File responses allow cross-origin reads because they are already public to anyone with the URL.

Updates keep the file name unless `--name` is given. The creator key or an admin can update or delete a file. Uploads stream in both directions: the CLI signs the file's SHA-256 in a header, the server authenticates the request before reading the body, verifies the hash while spooling to a temporary file, and then streams it to storage. Neither side holds the file in memory. Each file is capped by `PAGEUP_MAX_FILE_BYTES` (100 MiB by default). The storage backend can impose a lower limit; tg-s3 accepts 20 MB per object unless its large-file processor is configured, and the CLI reports either limit as a 413 error.

The `pageup-whagons` executable keeps credentials under the platform's `pageup-whagons` application config directory (`~/.config/pageup-whagons/config.json` on Linux) and uses mode `0600` where supported. This is intentionally separate from the legacy Gabriel Pageup config. `PAGEUP_CONFIG` selects another config file. Headless agents can use `PAGEUP_PRIVATE_KEY` with `PAGEUP_ENDPOINT` instead; treat the private-key value as a secret.

## Security model

Each request signs the HTTP method, path, Unix timestamp, random UUIDv7 nonce, and SHA-256 body hash. The server rejects unknown keys, modified requests, timestamps outside five minutes, and replayed nonces. Google login is used only to authorize a new upload-only device key. Admin-only endpoints list, add, or revoke keys.

Pages and sites are capped at 5 MiB of HTML. Sites are also capped at 100 HTML files. Pageup validates archives against path traversal, duplicate paths, non-HTML entries, and expanded-size abuse before storage. The Whagons deployment stores content, ownership metadata, and authorized public keys in `tg-s3`. Each page records its creator key, so that key and Pageup admins can update it at the same UUID. Anyone with a page URL can view it. UUID randomness and the absence of a listing provide link privacy, not access control.

## Development

The CLI uses the Go standard library. The server uses AWS SDK for Go v2 for S3-compatible storage.

```sh
make check
make build
make docker
```

The container builds CLI downloads for Linux, macOS, and Windows on amd64 and arm64. `scripts/render-coolify-dockerfile.sh` produces the self-contained Dockerfile used by the no-Git Coolify deployment.

Server settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PAGEUP_PUBLIC_URL` | derived from request | Canonical origin returned after upload |
| `PAGEUP_DATA_DIR` | `/data` | Persistent pages, files, and authorized-key store |
| `PAGEUP_DOWNLOADS_DIR` | `/app/downloads` | Cross-platform CLI binaries |
| `PAGEUP_BOOTSTRAP_KEYS` | required on first boot | JSON array containing at least one admin public key |
| `PAGEUP_MAX_PAGE_BYTES` | `5242880` | Maximum HTML bytes per page or site |
| `PAGEUP_MAX_FILE_BYTES` | `104857600` | Maximum bytes per shared file |
| `PAGEUP_LISTEN_ADDR` | `:8080` | HTTP listen address |
| `PAGEUP_WHAGONS_AUTH_URL` | Gonvex production endpoint | Authenticated developer-allowlist check |
| `PAGEUP_WHAGONS_PROJECT_ID` | production Whagons project UUID | Gonvex project header; distinct from the Firebase project ID |
| `PAGEUP_S3_ENDPOINT` | empty | S3-compatible origin; production uses `tg-s3` |
| `PAGEUP_S3_REGION` | `us-east-1` | Signing region |
| `PAGEUP_S3_BUCKET` | empty | Bucket containing Pageup data |
| `PAGEUP_S3_ACCESS_KEY_ID` | empty | S3 access key |
| `PAGEUP_S3_SECRET_ACCESS_KEY` | empty | S3 secret key |
| `PAGEUP_S3_PREFIX` | empty | Optional key prefix |

When `PAGEUP_S3_ENDPOINT` is set, Pageup requires the complete S3 configuration and checks the bucket at startup. Without it, Pageup uses `PAGEUP_DATA_DIR` for local development and tests.
