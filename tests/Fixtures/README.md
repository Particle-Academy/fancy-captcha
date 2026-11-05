# Provider response fixtures

Hand-written from each provider's PUBLISHED siteverify response format, not
captured from a live call. No test in this package reaches a provider: every
provider test fakes the HTTP client and forbids stray requests.

| file | format source |
|---|---|
| `turnstile-*.json` | Cloudflare Turnstile, "Server-side validation": `success`, `challenge_ts`, `hostname`, `error-codes`, `action`, `cdata`, `metadata.ephemeral_id` |
| `recaptcha-v2-success.json` | Google reCAPTCHA, "Verifying the user's response": `success`, `challenge_ts`, `hostname`, `error-codes` |
| `recaptcha-v3-success.json` | Google reCAPTCHA v3, same endpoint, plus `score` and `action` |
| `recaptcha-failure.json` | the documented `timeout-or-duplicate` error code |
| `hcaptcha-*.json` | hCaptcha, "Verify the User Response Server Side": `success`, `challenge_ts`, `hostname`, `credit`, `error-codes` |

Cloudflare's documented test keys (`1x0000000000000000000000000000000AA` and
friends) were NOT used: they still go to Cloudflare's siteverify endpoint, so
they need the network.
