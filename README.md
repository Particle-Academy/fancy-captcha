# fancy-captcha

Bot protection for Laravel 13 forms. One `Verifier` contract, four drivers:

| driver | what it checks | third party |
|---|---|---|
| `builtin` (default) | a honeypot, a signed form-render time (3 seconds to 6 hours), and optionally a single-use SHA-256 proof-of-work | none, no keys, no network |
| `turnstile` | Cloudflare Turnstile siteverify, plus hostname and action | Cloudflare |
| `recaptcha` | Google reCAPTCHA v2 (checkbox) or v3 (score threshold and expected action) | Google |
| `hcaptcha` | hCaptcha siteverify, plus hostname (and an optional enterprise risk score) | hCaptcha |

Providers are called over plain HTTP with Laravel's HTTP client. There are no SDKs.

The UI is [`@particle-academy/fancy-captcha-ui`](https://github.com/Particle-Academy/fancy-captcha-ui) on npm:
one React component for every driver.

```bash
composer require particle-academy/fancy-captcha
php artisan vendor:publish --tag=fancy-captcha-config   # optional
```

<!-- fancy-agents-note:start -->
> **For agents.** This package is listed on the Fancy MCP catalog server at
> `https://ui.particle.academy/mcp` (streamable HTTP, no API key; MCP id `fancy-ui`),
> with install commands and docs, alongside the rest of the kit. How an agent
> installs and uses this package is in [AGENTS.md](https://github.com/Particle-Academy/fancy-captcha/blob/main/AGENTS.md).
<!-- fancy-agents-note:end -->

## Protect a form

The middleware verifies a POST before your controller runs:

```php
Route::post('/register', RegisterController::class)->middleware('captcha:signup');
```

Or as a validation rule, in a form request:

```php
use FancyCaptcha\Rules\Captcha;

public function rules(): array
{
    return ['email' => ['required', 'email'], 'captcha' => [new Captcha('signup')]];
}
```

Both throw a validation error under the `captcha` key (`fancy-captcha.error_key`) with one
generic message: *"We could not verify this submission. Please reload the page and try
again."* The specific reason (`too_fast`, `honeypot_filled`, `pow_replayed`,
`provider_unreachable`, ...) goes to the log only. Telling a bot which check it tripped
teaches it.

Using both on the same request is safe: the verdict is remembered on the request, so a
proof-of-work is redeemed once.

Anywhere else: `Captcha::verify($request, 'signup')->passed`.

## Give the UI its props

With Inertia installed, every page gets a `fancyCaptcha` prop automatically, with a fresh
signed timestamp per render. Without Inertia, pass `Captcha::props()` to your view yourself.

```php
[
    'provider' => 'builtin',         // or turnstile, recaptcha-v2, recaptcha-v3, hcaptcha
    'siteKey' => null,               // the PUBLIC key only; never a secret
    'action' => null,
    'fields' => ['honeypot' => 'contact_fax', 'started' => '_captcha_started', 'pow' => '_captcha_pow', 'token' => '_captcha_token'],
    'started' => '1762344000.Qm9...', // signed render time
    'pow' => ['enabled' => false, 'difficulty' => 18, 'challengeUrl' => '/fancy-captcha/challenge'],
    'consentCategory' => null,
    'configured' => true,
]
```

The field names are constants on both sides (`FancyCaptcha\Fields` here, `CAPTCHA_FIELDS` in
the UI). Rename them in `fancy-captcha.fields` and the UI follows, because it reads the
names from the props.

## The built-in checks

- **Honeypot.** A field named `contact_fax`, hidden from people, screen readers and the
  keyboard. Form-filling bots fill it. Any value refuses.
- **Signed timing.** The render time, HMAC-SHA256-signed under a key derived from `APP_KEY`.
  A submission under `min_seconds` (3) is a script; a form older than `max_seconds`
  (6 hours) has to be reloaded. It is signed rather than encrypted because the time is not a
  secret, only its integrity matters, and an HMAC check reads a fixed-length string with no
  decoding and no regular expression. Rotating `APP_KEY` invalidates open forms.
- **Proof-of-work** (`CAPTCHA_POW=true`). The browser fetches a challenge from
  `GET /fancy-captcha/challenge`, searches for a nonce so that `SHA-256("<id>:<nonce>")`
  starts with `difficulty` zero bits (18 by default, in a Web Worker), and the server checks
  it with one hash. A challenge is random, lives 5 minutes, and is **accepted once**: it is
  marked spent with an atomic cache `add()` before the hash is checked, so a replay, a
  concurrent double submit, or a second guess against the same challenge all fail. Use a
  cache store whose `add()` is atomic (redis, memcached, database, dynamodb, array), not
  `file`.

What it does not do, honestly: a determined attacker with a real browser, or native code
for the proof-of-work, gets through the built-in checks. They stop the cheap, high-volume
bots (random names, dotted-gmail sign-ups). For the rest, add a provider.

The challenge route is throttled per IP (`routes.per_minute`, 30).

## Providers

```dotenv
CAPTCHA_DRIVER=turnstile
TURNSTILE_SITE_KEY=...
TURNSTILE_SECRET_KEY=...
```

`RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET_KEY` / `RECAPTCHA_VERSION=v3` and
`HCAPTCHA_SITE_KEY` / `HCAPTCHA_SECRET_KEY` work the same way.

**Fails closed.** With both keys set, anything short of a well-formed `"success": true` is a
refusal: a connection error, a timeout (`timeout`, 3 seconds; `connect_timeout`, 2), any
non-2xx status, a redirect, a body that is not a JSON object, a reported hostname that is
not the request's (or one of `fancy-captcha.hostnames`), a reported action that is not the
expected one, or a v3 score below `score_threshold`. An outage must not be the way in.

**Unconfigured.** With a provider selected and a key missing, **production refuses every
submission** and logs an error. Local and testing fall back to the built-in checks and log
a warning that says so, so a missing key is loud rather than a silent bypass.

The honeypot and timing also run in front of a provider (`builtin.with_providers`), and a
refused submission never reaches the provider.

Tokens are bounded before anything is sent: a string of at most `max_token_length`
characters (2048 for Turnstile, as Cloudflare documents) from a fixed token alphabet,
checked with `strspn`, not a regular expression.

## Consent (optional, with fancy-compliance)

A third-party widget sets cookies and talks to its provider, so a host may want it behind
consent:

```php
'consent' => ['category' => 'functional', 'fallback_pow' => true],
```

When `particle-academy/fancy-compliance` is installed and the visitor has granted the
category, the provider runs. When they have not, or fancy-compliance is not installed, the
**built-in checks run instead, with proof-of-work** (`fallback_pow`), because refusing
consent must not be the cheap way past the check. The UI makes the same choice from the
same props.

fancy-compliance is not a dependency. Its `ConsentGate` contract is asked only when it
exists and is bound.

## Logging

Every refusal is one `info` line, `fancy-captcha refused a submission.`, with `driver`,
`reason`, `action`, `route`, and numbers or provider error codes where useful. **Never a
token, a solution, a timestamp or a secret**: provider error codes are logged only when they
have the documented `lower-case-with-dashes` shape, and an exception is logged by class name,
because its message can carry the request. The IP address is left out unless
`log.ip` is true. `log.channel` picks the channel.

## Testing your app

```php
use FancyCaptcha\Facades\Captcha;

$fake = Captcha::fake();            // every verification passes
$this->post('/register', [...])->assertRedirect('/home');
$fake->assertVerified('signup');

Captcha::fake(passes: false);        // every verification fails
$fake->fails(); $fake->passes();     // switch mid-test
$fake->assertNotVerified();
$fake->assertVerifiedCount(1);
```

`Captcha::fake()` throws in production, where it would be a bypass.

## Custom drivers

```php
Captcha::extend('friendly', fn ($app, array $config) => new FriendlyVerifier($config));
```

A driver implements `FancyCaptcha\Contracts\Verifier` and must fail closed.

## Licence

MIT.
