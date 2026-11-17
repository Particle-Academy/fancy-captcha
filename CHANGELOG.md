# Changelog

Notable changes to `particle-academy/fancy-captcha`.

**Pre-1.0: breaking changes land in MINOR releases.** Read those entries before upgrading.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Changed

- **Docs:** `AGENTS.md` is now the guide to using this package (install, its entries on the Fancy MCP catalog server, API essentials, traps). The contributor notes it held moved to `CONTRIBUTING.md`, and `CLAUDE.md` is now a symlink to it. The README points to the MCP server and to `AGENTS.md`. No code changed; nothing to do.

## [0.1.0] - 2026-11-05

### Added

- **One `Verifier` contract with four drivers**, chosen by `fancy-captcha.driver`:
  `builtin` (the default), `turnstile`, `recaptcha` (v2 checkbox or v3 with
  `score_threshold` and expected action) and `hcaptcha`. Providers are called over plain
  HTTP with Laravel's HTTP client, with no SDK and no new dependency.
- **Built-in checks:** a honeypot field (`contact_fax`), a form-render time signed with
  HMAC-SHA256 under a key derived from `APP_KEY` (3 seconds minimum, 6 hours maximum), and
  optional proof-of-work: a random, 5-minute, cache-stored challenge from
  `GET /fancy-captcha/challenge` (throttled per IP), a SHA-256 leading-zero-bits search in
  the browser, one hash to verify, and each challenge accepted once.
- **Fails closed.** Network errors, timeouts (3 seconds by default), non-2xx statuses,
  redirects, unreadable bodies, a wrong hostname or action, and low v3 scores are all
  refusals. A provider selected without keys refuses everything in production and falls back
  to the built-in checks, with a logged warning, elsewhere.
- **The `captcha:<action>` middleware, the `Rules\Captcha` validation rule and the
  `Captcha` facade.** One generic message for the visitor; the reason goes to the log, which
  never carries a token, a solution, a timestamp or a secret. The verdict is memoised per
  request, so the middleware and the rule together redeem a proof-of-work once.
- **Optional consent gating** with `particle-academy/fancy-compliance` (not a dependency):
  `consent.category` puts the provider behind a consent category, with the built-in checks
  and proof-of-work as the fallback when it is refused.
- **Props for `@particle-academy/fancy-captcha-ui`**, shared with Inertia as `fancyCaptcha`
  when Inertia is installed. Field names are shared constants (`FancyCaptcha\Fields`).
- **`Captcha::fake()`** for host tests, with `passes()`, `fails()`, `assertVerified()`,
  `assertNotVerified()` and `assertVerifiedCount()`. Refused in production.
- Tests: Pest 5 on a hand-built Laravel 13 kernel, no testbench, no network.
  `laravel/framework` is a dev dependency under the estate's carve-out for the framework a
  package integrates with.

**Consumer action:** new package. Install, then either keep the default built-in driver or
set a provider's two keys. If you choose a provider, set the keys before deploying:
production refuses every submission until both are present.
