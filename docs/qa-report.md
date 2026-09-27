# Daymark QA report — security & full-suite audit

**Date:** 2026-09-27
**Commit audited:** `abfbb63` — *Bridge captured weather into Simple Location at publish time*
**Plugin version:** 0.17.0
**Scope:** full QA pass — static analysis, automated test suite, dependency audit, and a
manual security review of the REST layer, admin screens, frontend app shell, uploads,
inbound content ingestion, and outbound HTTP paths.

**Verdict:** all automated checks are green. One confirmed HIGH-severity security defect
(Finding 1) and three LOW findings should be addressed. No blocking release issue beyond
Finding 1.

**Tracked as:** [#438](https://github.com/jeffpaul/daymark/issues/438)

---

## 1. Automated checks — all passing

| Check | Command | Result |
|---|---|---|
| PHP syntax | `php -l` on all non-vendor PHP | **PASS** — clean |
| Coding standards (plugin) | `vendor/bin/phpcs` | **PASS** — 8/8 files |
| Coding standards (tests) | `composer phpcs-tests` | **PASS** — 8/8 files |
| PHP 8.2+ compatibility | `composer phpcompat` | **PASS** — no violations |
| JS syntax | `node --check` on all `assets/*.js` | **PASS** — clean |
| JSON validity | `jq empty` on all 5 JSON files | **PASS** |
| Changelog sync | `bin/sync-changelog.sh --check` | **PASS** — readme.txt in sync |
| Unit/integration tests | `WP_TESTS_DIR=… vendor/bin/phpunit --do-not-cache-result` | **PASS** — 931 tests, 2459 assertions |
| Composer advisories | `composer audit` | **PASS** — none |
| Composer manifest | `composer validate` | **PASS** — valid |
| npm advisories | `npm audit --package-lock-only` | **PASS** — 0 vulnerabilities |

**PHP Notice noise during the run** (`A feed could not be found at …`, `is invalid XML`) comes
from WordPress core's bundled SimplePie, emitted by tests that deliberately point the feed
source at non-feed URLs. Not a Daymark defect.

### Not covered

| Check | Why not |
|---|---|
| Playwright E2E suite | Requires `npm ci` + Playwright browser install + a live authenticated site. Not available in this environment. |
| `tests/smoke.sh` (WP-CLI, 57 assertions) | Requires a live site with the plugin active and a WP-CLI wrapper. Not available. |
| wp.org plugin-check | CI-only job (`.github/workflows/plugin-check.yml`); no local equivalent. |

---

## 2. Findings

| # | Severity | Summary |
|---|---|---|
| 1 | **HIGH** | SSRF guard is never re-applied on HTTP redirects |
| 2 | LOW | CSS injection / UI redressing via remote subscription content |
| 3 | LOW | Author's real email disclosed to third-party sites without notice |
| 4 | LOW | Site-wide subscription set gated only at `edit_posts` |
| 5 | INFO | `GET /subscription-posts/{id}/oembed` never asserts the post type |
| 6 | INFO | Site URL disclosed in the `User-Agent` of every outbound request |
| 7 | INFO | `CLAUDE.md:305` contradicts shipped code (weather bridge) |
| — | *False positive* | ~~Stored XSS via `esc_js()` in the Unsubscribe `confirm()`~~ — disproved, see §4 |

---

### Finding 1 — HIGH — SSRF guard is never re-applied on HTTP redirects

**The gap.** `Daymark_Subscription_Url_Guard::check()` is the plugin's strict outbound-URL
gate. It rejects loopback, RFC1918 private ranges, **link-local `169.254.0.0/16`**, **CGNAT
`100.64.0.0/10`**, **`240.0.0.0/4` reserved**, IPv6 loopback / unique-local / link-local,
IPv4-mapped IPv6 equivalents of all of the above, non-standard ports, and embedded userinfo
(`class-subscription-url-guard.php:331`). `tests/test-subscription-url-guard.php` locks all of
this in with 19 passing tests.

The guard is called at 13 sites — but **always on the initial URL only**:

```
includes/class-subscription-opengraph.php:109
includes/class-comment-delivery.php:181, 292
includes/class-subscription-opml.php:354, 472
includes/class-subscription-poller.php:582
includes/class-subscriptions.php:275
includes/class-subscription-oembed.php:92
includes/sources/class-subscription-source-microformats.php:1155
includes/sources/class-subscription-source-feed.php:1087
includes/sources/class-subscription-source-wordpress.php:141, 638
includes/class-websub-subscriber.php:128
```

The plugin registers **no** `requests.before_redirect`, `pre_http_request`,
`http_request_host_is_external`, or `http_allowed_safe_ports` hook — confirmed by search
across `includes/`, `assets/`, `templates/`, and `daymark.php`.

Every outbound fetch then uses `wp_safe_remote_get()` / `wp_safe_remote_post()`, which sets
`reject_unsafe_urls => true` and therefore re-validates the URL — including **every redirect
hop** — with core's `wp_http_validate_url()` via `WP_Http::validate_redirects()`.

**Why core's check is not enough here.** Reading the core source directly,
`wp_http_validate_url()` rejects only:

- `127.0.0.0/8`
- `10.0.0.0/8`
- `0.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

It **permits** `169.254.0.0/16`, CGNAT `100.64.0.0/10`, and `240.0.0.0/4` — precisely the
three ranges Daymark's own guard blocks and has tests for. So the plugin's SSRF hardening is
bypassed the moment a request is redirected.

**Exploit path.** An attacker who controls a site Daymark subscribes to (or who can otherwise
get a subscription established to a host they control) returns:

```
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

The poller follows it (`includes/class-subscription-poller.php:615`, `redirection => 5`) and
stores the response body as `body_content` post meta (`:662`). That meta is returned verbatim
by `GET /daymark/v1/subscription-posts/{id}` (`includes/class-rest-controller.php:2775`) to any
user passing `permissions_check` — which is `edit_posts` + nonce (`:857`), i.e. **any Author or
above**.

**Impact:** on a cloud-hosted site, exfiltrating instance-role IAM credentials to any
Author-level user. More generally, a pivot to arbitrary internal HTTP services, with the
response body readable through the REST API.

**Blast radius** — all 10 outbound call sites share the gap:

| Call site | Line | Redirects |
|---|---|---|
| `includes/class-subscription-poller.php` | 603 | 5 |
| `includes/class-subscription-html-cache.php` | 105 | 5 |
| `includes/sources/class-subscription-source-wordpress.php` | 437 | 5 |
| `includes/class-comment-delivery.php` (POST, native comment) | 302 | 5 |
| `includes/class-comment-delivery.php` (GET, origin signals) | 439 | 5 |
| `includes/class-websub-subscriber.php` (POST) | 145 | 5 |
| `includes/class-subscription-opengraph.php` | 146 | 3 |
| `includes/class-geocoder.php` (×2) | 171, 253 | default |
| `includes/class-publisher.php` (Open-Meteo weather) | 2106 | default |

The `class-publisher.php` fetch targets a hardcoded host with only lat/lng interpolated, so it
is deliberately not one of the 13 guarded call sites — it is listed here only because it shares
the same redirect gap.

**Suggested remediation.** Register a `requests.before_redirect` handler that re-runs
`Daymark_Subscription_Url_Guard::check()` on each `$location` and rejects the redirect when it
fails — a single choke point that covers all ten call sites, matching the "one shared mechanism
over per-feature variants" pattern this codebase already uses for feed autodiscovery,
payload building, and engagement markup. Add regression tests asserting that a redirect to
`169.254.169.254`, a CGNAT address, and a `240/4` address is refused, alongside the existing
19 direct-URL tests.

---

### Finding 2 — LOW — CSS injection / UI redressing via remote subscription content

`wp_kses_post()` preserves `style` attributes, and the app shell's CSP sets
`style-src 'unsafe-inline'` (`templates/app-shell.php:49`). A hostile subscribed site can
therefore inject arbitrary CSS into the authenticated app shell — overlaying, hiding, or
spoofing Daymark's own chrome.

- Ingest: `includes/class-subscription-poller.php:660` (`wp_kses_post( extract_body_html( … ) )`)
- Transport: `includes/class-rest-controller.php:2775` (`body_content`, returned raw)
- Sinks: `assets/app.js:7822`, `:7847`, `:8046` (`innerHTML`)

**No script execution** — the CSP `script-src` is nonce-only with no `unsafe-inline`, and
`wp_kses_post()` strips `<script>`. This is UI redressing / clickjacking-adjacent, not XSS.

**Suggested remediation.** Either strip `style` attributes from ingested subscription HTML
(alongside the existing extraction passes), or drop `'unsafe-inline'` from `style-src` and
move the app shell's own inline styles to a nonce. The former is smaller and leaves the app
shell's own styling untouched.

---

### Finding 3 — LOW — Author's real email disclosed to third-party sites without notice

The native comment fallback posts to the origin site's unauthenticated `wp/v2/comments`
endpoint including:

```php
'author_name'  => $user->display_name,
'author_email' => $user->user_email,
'author_url'   => home_url( '/' ),
```

(`includes/class-comment-delivery.php:302-315`)

This mirrors what WordPress's own comment form does, so it is arguably expected — but it is a
real personal-data disclosure to a third party, and the app shell gives the user no indication
that it happens. Worth surfacing in the comment composer copy and/or the readme privacy
callouts.

---

### Finding 4 — LOW — Site-wide subscription set gated only at `edit_posts`

`Daymark_Admin_Subscriptions::CAPABILITY = 'edit_posts'` (`includes/class-admin-subscriptions.php:51`).

Subscriptions are a **single shared, site-wide** table, not per-user. Any Author — a
deliberately low-trust role on a multi-author site — can therefore:

- subscribe the whole site to an arbitrary external host,
- **unsubscribe**, which trashes that subscription's cached posts (irreversible from the UI),
- edit any subscription's site name,
- trigger outbound fetches to third-party hosts on the site's behalf.

Consider a higher gate (`manage_options`, matching wp-admin convention) for destructive
actions specifically — unsubscribe, import, OPML export — while leaving read and add at
`edit_posts`. That keeps the deliberate, documented "not `manage_options`" decision intact for
the common path while protecting the destructive ones.

---

### Finding 5 — INFO — oEmbed preview route never asserts the post type

`get_subscription_post_oembed()` (`includes/class-rest-controller.php:2808`) reads `link_url`
post meta from an arbitrary post ID without calling `assert_subscription_post()`. Its siblings
are inconsistent: like/unlike do call it (`:2954`, `:3027`), while
`get_subscription_post_full_content()`, this route, and `comment_on_subscription_post()` do not.

Not currently exploitable — `link_url` is only ever written by the subscription ingester
(`class-subscription-poller.php:408`), and both resolvers re-apply the SSRF guard themselves
(`opengraph.php:109`, `oembed.php:92`). But it consumes the shared rate-limit bucket and widens
the surface if `link_url` is ever set by another plugin or code path. Adding the assert for
consistency would be a one-line change.

---

### Finding 6 — INFO — Site URL disclosed in the `User-Agent` of every outbound request

Every outbound fetch sends:

```php
'user-agent' => 'Daymark/' . DAYMARK_VERSION . '; ' . home_url( '/' ),
```

This tells every third-party host the exact site being fetched. The plugin name + version is
useful; the site URL is not, and is a minor fingerprinting aid. Low impact — flagging for a
future hardening pass rather than anything urgent.

---

### Finding 7 — INFO — `CLAUDE.md:305` contradicts shipped code

`CLAUDE.md` is this repo's authoritative architectural record. The Checkin decision row still
states that weather bridging into Simple Location was:

> "deliberately **not** attempted, since Simple Location's own weather-storage schema could not
> be similarly confirmed in this environment, and guessing at a wrong meta shape would be worse
> than leaving it unbridged — split out into its own tracking issue, [#397]"

That is now stale. Commit `abfbb63` shipped the weather bridge, and `CHANGELOG.md` has a
correct `## [Unreleased] → ### Added` entry linking [#397]. The commit's `Co-authored-by`
trailers are compliant, and `bin/sync-changelog.sh --check` confirms `readme.txt` is in sync —
so this is a `CLAUDE.md` row that needs updating to match reality, not a changelog gap.

---

## 3. What is already solid

Worth recording, since these were all specifically checked:

- **All 34 REST routes** are gated behind `permissions_check` (`edit_posts` + `X-WP-Nonce`).
  No unauthenticated write path.
- **All SQL** uses `$wpdb->prepare()`.
- **File uploads** are validated by MIME (not extension) *and* capped both per-file and per-request
  (`Daymark_Publisher::validate_file_list()`, `MAX_TOTAL_FILE_BYTES`).
- **Alt-text writes** are scoped to a Mark's own media (the historical IDOR is fixed).
- **OPML import** parses with `LIBXML_NONET | LIBXML_NOBLANKS` and never a DTD/entity-loading
  flag, so XXE fails closed.
- **`apply_alt_map()` and `media_order`** are both server-validated (exact permutation / own-media
  scope) rather than trusted from the client.
- **Uninstall cleanup** and legacy `moment_*` migration removal are consistent with the 0.9.0
  decision recorded in `CLAUDE.md`.
- **The service worker** caches only `app.css`/`app.js`/`offline-boot.js` and a nonce-redacted
  `config.json` — never REST responses, nonces, admin data, or HTML.
- **`Daymark_Like_Visibility`** correctly layers five independent suppression mechanisms so Like
  Marks stay out of the feed, REST, sitemap, oEmbed, and queries.

---

## 4. Disproved finding — the `esc_js()` "stored XSS"

A review pass flagged `includes/class-admin-subscriptions.php:1784` as a stored XSS:

```php
array( 'onclick' => 'return confirm(\'' . esc_js( $confirm_message ) . '\');' )
```

The concern was that `esc_js()` does not HTML-encode `&`, so an entity-encoded quote in a
subscription's `site_title` would decode at the HTML-parsing stage and break out of the
JS string literal.

**This is not exploitable.** Running WordPress's actual `esc_js()` against a
`&#039;);alert(document.domain);//` payload produces:

```
"Unsubscribe from x\');alert(document.domain);//? This cannot be undone."
```

Current core converts the entity back to a literal `'` *and then* `addslashes()` it, yielding
`\'`. The rendered attribute is therefore a correctly-escaped single-quoted JS string literal:

```html
onclick="return confirm('Unsubscribe from x\');alert(document.domain);//? …');"
```

The analysis that flagged it assumed an older `esc_js()` implementation. No action needed,
though using `esc_js()` inside an HTML attribute is a fragile pattern in general — it depends
on `esc_js()`'s internal ordering, which has changed across WordPress versions.

---

## 5. Recommended order of work

1. **Finding 1** — the `requests.before_redirect` re-validation choke point + regression tests.
   This is the only item with real security impact.
2. **Finding 7** — one-paragraph `CLAUDE.md:305` update, trivial.
3. **Finding 2** — strip `style` from ingested subscription HTML; small, contained.
4. **Finding 4** — raise the capability gate on destructive subscription actions only.
5. **Finding 3** — surface the email disclosure in the comment composer copy / readme.
6. **Findings 5 & 6** — opportunistic cleanups.
