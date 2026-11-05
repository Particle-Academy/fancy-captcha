# fancy-captcha code map

`FancyCaptcha\` is a PHP 8.4 library for Laravel 13: one `Verifier` contract with a built-in
driver (honeypot, signed timing, proof-of-work) and Turnstile, reCAPTCHA and hCaptcha drivers
over Laravel's HTTP client. Its UI is `@particle-academy/fancy-captcha-ui`; `props()` is the
contract between them.

## Where things are

- `CaptchaManager` (singleton, facade `Captcha`): `verify`, `passes`, `props`, `fields`,
  `issueChallenge`, `failureMessage`, `extend`, `fake`. Picks the driver per request
  (config, then consent), runs the built-in checks in front of a provider, memoises the
  verdict on `$request->attributes`, logs refusals.
- `Drivers\BuiltinVerifier`: honeypot, then timestamp, then (if required) proof-of-work.
- `Drivers\SiteverifyVerifier`: the shared provider call and every fail-closed branch.
  `TurnstileVerifier`, `RecaptchaVerifier` (v3 score and action), `HcaptchaVerifier`
  (sends `sitekey`, optional enterprise score).
- `Support\FormTimestamp`: `<unix>.<base64url HMAC>`, key derived from APP_KEY.
- `Support\ProofOfWork`: issue and redeem; `leadingZeroBits`.
- `Fields`: default field names, mirrored by the UI's `CAPTCHA_FIELDS`.
- `Rules\Captcha` (implicit rule), `Http\VerifyCaptcha` (alias `captcha:<action>`),
  `Http\ChallengeController` (`GET {prefix}/challenge`, throttled by the `fancy-captcha`
  limiter), `Testing\CaptchaFake`.
- `CaptchaServiceProvider`: DEEP-merges the config defaults (a shallow merge drops nested
  defaults such as a provider's `endpoint`), registers the route, alias, limiter and the
  optional Inertia share.

## Invariants a change must keep

- **Fail closed.** In `SiteverifyVerifier::verify` every branch that is not a well-formed
  `success === true` returns a refusal, including any `Throwable`.
- **A keyless provider refuses everything in production**; elsewhere it falls back to the
  built-in checks with a warning.
- **A proof-of-work challenge is accepted once**: entry must exist, spent marker added with
  atomic `add()`, entry forgotten, THEN the hash is checked.
- **Nothing hostile reaches a regex.** Timestamp, solution and token are checked with
  `strlen` / `strspn` / `hash_equals` after a length bound.
- **Logs carry codes and numbers, never values.** No token, solution, timestamp, secret,
  reported hostname or action; exceptions by class name; provider codes only of the shape
  `[a-z0-9-]{1,64}`; IP only with `log.ip`.
- **The visitor gets `failureMessage()` only.**
- **Consent-refused (or fancy-compliance absent) means the built-in fallback**, with
  proof-of-work unless `consent.fallback_pow` is false.
- `props()` never contains a secret, and its shape changes only additively.
- `fake()` throws in production.

## Tests

Pest 5 on a hand-built kernel (`tests/Support/TestApp.php`, no testbench), the array cache.
Provider tests use `tests/Fixtures/*.json` (hand-written from the published formats) with
`Http::fake()` and `Http::preventStrayRequests()`. `tests/Stubs/` stands in for Inertia's
facade and fancy-compliance's `ConsentGate` (autoload-dev only). Pest invokes closures found
in a dataset, so datasets name a failure and the test builds the closure.
`php tests/lint.php` lints every PHP file.
