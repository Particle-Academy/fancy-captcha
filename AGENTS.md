# Using particle-academy/fancy-captcha — guide for agents

How an agent installs and uses this package in a consumer app. What the package
is, is in [README.md](./README.md). Notes for working ON this repo's code are in
[CONTRIBUTING.md](./CONTRIBUTING.md).

## Install

```bash
composer require particle-academy/fancy-captcha
php artisan vendor:publish --tag=fancy-captcha-config   # optional
```

- **Requires** PHP `^8.4` and Laravel `^13.0`.
- **Optional:** `inertiajs/inertia-laravel` (shares the props with every page as
  `fancyCaptcha`), `particle-academy/fancy-compliance` (gates a provider behind a
  consent category).
- **The UI** is a separate npm package, `@particle-academy/fancy-captcha-ui`.

## Find it on the Fancy MCP server

The catalog server is `https://ui.particle.academy/mcp` (streamable HTTP, no API
key; MCP id `fancy-ui`). This package is the registry entry `fancy-captcha`; its UI
is `fancy-captcha-ui`.

| Need | Tool |
|---|---|
| Find a server-side package by capability | `search-backend-packages` (stack `php`) |
| Exact install commands for a slug | `install-instructions` |
| Is the app on current versions? | `check-versions` |

## API essentials

- **Protect a route:** middleware `captcha:<action>`, e.g.
  `->middleware('captcha:signup')`.
- **Or a validation rule:** `'captcha' => [new \FancyCaptcha\Rules\Captcha('signup')]`.
- **Anywhere else:** `Captcha::verify($request, 'signup')->passed`.
- Both raise one generic validation error under the `captcha` key
  (`fancy-captcha.error_key`); the specific reason goes to the log only.
- **Props for the UI:** automatic as `fancyCaptcha` with Inertia; otherwise pass
  `Captcha::props()` to the view yourself. It never contains a secret.
- **Driver:** `CAPTCHA_DRIVER` = `builtin` (default, no keys), `turnstile`,
  `recaptcha` or `hcaptcha`, with that provider's `*_SITE_KEY` / `*_SECRET_KEY`.
  `CAPTCHA_POW=true` turns on the built-in proof-of-work.
- **Host tests:** `Captcha::fake()` (passes) or `Captcha::fake(passes: false)`, then
  `assertVerified('signup')`, `assertNotVerified()`, `assertVerifiedCount(n)`.
- **Custom driver:** `Captcha::extend('name', fn ($app, array $config) => ...)`,
  implementing `FancyCaptcha\Contracts\Verifier`; it must fail closed.

## Traps

- **A missing provider key refuses every submission in production.** Local and
  testing fall back to the built-in checks with a warning.
- **Proof-of-work needs a cache store with an atomic `add()`** (redis, memcached,
  database, dynamodb, array), not `file`.
- **Rotating `APP_KEY` invalidates open forms** (the timestamp is signed with a key
  derived from it).
- **Field names come from the props.** Rename them in `fancy-captcha.fields`, never in
  the UI alone.
- **`Captcha::fake()` throws in production.**

## Agents and the captcha itself

An agent may read whether a form is protected and what state it is in. It must never
solve or submit a captcha for a person: that is the one thing the check exists to tell
apart. Nothing in this package helps it do so.
