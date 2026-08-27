# Pageup for Whagons

Pageup turns a local HTML file or small HTML-only directory into an unlisted, shareable URL with one command:

```console
$ pageup report.html
https://pageup.whagons.com/019c...

$ pageup ./experiment
https://pageup.whagons.com/019d.../
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
pageup auth login
pageup doctor
```

Use `pageup auth login --no-open` on a headless machine and open the printed URL elsewhere. Pageup creates one upload-only key for the device. Removing the email from the Whagons developer allowlist prevents new device authorization; existing device keys can be revoked by a Pageup admin.

Every Pageup CLI binary also contains the complete `$pages` agent skill. Install it into the detected Codex or `~/.agents` skill directory with:

```sh
pageup skill install
```

Use `pageup skill show` to inspect the embedded instructions, `--harness project` to install under `./.agents/skills`, or `--target DIR` for another agent harness. Existing skill files are preserved unless `--force` is supplied.

The manual pairing commands remain available for the bootstrap administrator:

```sh
PAGEUP_CONFIG=~/.config/pageup-whagons-admin.json pageup init --endpoint https://pageup.whagons.com --name "Pageup admin"
```

The command prints a public key and an approval command. Run that approval command on a computer which already has an admin credential, then verify the new computer:

```sh
pageup doctor
pageup example.html
```

This manual flow is not needed for normal team onboarding. It never moves a private key between computers. Use `pageup keys list` and `pageup keys revoke KEY_ID` from the bootstrap admin identity to audit or revoke devices.

## CLI

```text
pageup file.html                     upload a file; print its URL
pageup ./site                        upload an HTML-only directory
pageup -                             upload HTML from stdin
pageup --json file.html              return id, URL, and revision state as JSON
pageup --open file.html              upload and open in the default browser
pageup update URL file.html          update HTML without changing the URL
pageup update URL ./site             update or convert to a multi-page site
pageup update UUID -                 update by id with HTML from stdin
pageup auth login                    authorize this device with Google
pageup doctor                        test connectivity and authentication
pageup whoami                        show the active key
pageup public-key                    print this device's public key
pageup skill show                    print the embedded Pages skill
pageup skill install                 install Pages into an agent harness
pageup keys add --name NAME PUBKEY   authorize another device
pageup keys list                     list authorized devices
pageup keys revoke KEY_ID            revoke a device
```

For a multi-page site, pass a directory containing `index.html` at its root. Pageup recursively preserves up to 100 `.html` files, so links such as `href="about.html"` and `href="docs/"` work as expected. A nested `docs/index.html` is served at the directory-style URL `/docs/`. Directories may contain only HTML: keep CSS and JavaScript inline and use remote URLs for images, fonts, and other assets. The combined uncompressed HTML remains subject to the 5 MiB limit.

Credentials live at `~/.config/pageup/config.json` on Linux, the normal application config directory on macOS or Windows, and use mode `0600` where supported. `PAGEUP_CONFIG` selects another config file. Headless agents can use `PAGEUP_PRIVATE_KEY` with `PAGEUP_ENDPOINT` instead; treat the private-key value as a secret.

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
| `PAGEUP_DATA_DIR` | `/data` | Persistent pages and authorized-key store |
| `PAGEUP_DOWNLOADS_DIR` | `/app/downloads` | Cross-platform CLI binaries |
| `PAGEUP_BOOTSTRAP_KEYS` | required on first boot | JSON array containing at least one admin public key |
| `PAGEUP_MAX_PAGE_BYTES` | `5242880` | Maximum HTML bytes per page or site |
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
