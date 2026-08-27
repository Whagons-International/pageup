---
name: pages
description: Create, update, and publish self-contained HTML artifacts and small HTML-only sites through the authenticated Whagons Pageup CLI at pageup.whagons.com. Use for project reports, handoffs, demos, dashboards, comparisons, and other HTML meant for human review.
---

# Pages

Use Pageup to turn HTML into an unlisted, shareable URL. A single standalone HTML file is the default; a small directory is available when the artifact genuinely benefits from multiple HTML pages. Treat creating and updating pages as authenticated, and viewing as public to anyone who has the URL.

## Install and authenticate

If `pageup` is not installed, install the Whagons build.

macOS or Linux:

```sh
curl -fsSL https://pageup.whagons.com/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://pageup.whagons.com/install.ps1 | iex
```

Authorize the device with a Google account on the Whagons developer allowlist:

```sh
pageup auth login
pageup doctor
```

`pageup auth login` opens a browser. If the environment cannot open one, use `pageup auth login --no-open` and give the printed URL to the user. The server checks the same developer allowlist used by Whagons developer mode. Pageup stores a revocable device key after login and does not retain the Google token.

## Build the artifact

1. Gather verifiable facts before designing the page. For project reports, inspect the relevant changes, tests, commit state, and remaining work. Distinguish completed, in-progress, blocked, and proposed work.
2. Prefer one standalone HTML file with inline CSS and optional inline JavaScript. When multiple pages materially improve the artifact, create a directory with `index.html` at its root and no more than 100 `.html` files. Nested folders are supported. Keep CSS and JavaScript inline and use external URLs for images, fonts, and other assets; non-HTML files cannot be uploaded.
3. Use a deliberate visual direction suited to the content. Make the result responsive and accessible with semantic HTML, a useful title, viewport metadata, readable contrast, keyboard support, and reduced-motion handling where animation exists.
4. For completion summaries, favor this information order: outcome, what changed, proof or verification, how to use it, and next steps. For progress pages, include an as-of time and clearly labeled status, evidence, blockers, and next actions.
5. Include only information needed for the intended audience. Never include private keys, credentials, tokens, secrets, sensitive logs, or unnecessarily private source material. Assume uploaded pages persist.

Save the artifact in the workspace when it is a useful project deliverable; otherwise use a temporary HTML file and remove it after publishing.

## Publish with Pageup

Confirm connectivity and authentication when the environment is unfamiliar:

```sh
pageup doctor
```

Upload a file:

```sh
pageup path/to/report.html
```

Upload a multi-page HTML directory:

```sh
pageup path/to/site
```

The directory must contain `index.html` at its root. Relative links such as `href="about.html"` work, and `docs/index.html` is available at `docs/`. The total uncompressed HTML is capped at 5 MiB.

Upload generated HTML from standard input:

```sh
generate-html | pageup -
```

Use structured output when another command must consume the result:

```sh
pageup --json path/to/report.html
```

Keep an existing URL current when the user names that page or the artifact is an ongoing report:

```sh
pageup update PAGE_URL path/to/report.html
pageup update PAGE_URL path/to/site
generate-html | pageup update PAGE_UUID -
```

`pageup update` accepts either the full Pageup URL or its UUIDv7, replaces the HTML in place, and keeps the same page UUID. It can also convert a standalone page to a site or a site back to a standalone page; site URLs include a trailing slash so relative links resolve correctly. The key that created a page can update it; an admin key can update any page. Pages created before ownership tracking are admin-only until first updated by an admin. Use a new upload when the artifact should have a distinct URL or history boundary.

Do not print, copy, or commit `~/.config/pageup/config.json`. If authentication is missing, run `pageup auth login`. Never transfer a private key between devices.

## Verify and hand off

Open or preview the result and check the important content at desktop and narrow widths. For a site, follow representative relative links and nested directory links as well. Also verify that the returned URL responds successfully and contains the current revision. Correct problems in the local HTML, then update the same UUID when continuity matters or upload a new page when it does not.

Return the final URL prominently with a one-line description. Mention that the page is public-but-unlisted when the audience could mistake the link for access-controlled content.
