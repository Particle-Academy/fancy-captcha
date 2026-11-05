<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Driver
    |--------------------------------------------------------------------------
    |
    | builtin   honeypot + signed form timing (+ proof-of-work when enabled).
    |           No third party, no keys, no network. The default.
    | turnstile Cloudflare Turnstile.
    | recaptcha Google reCAPTCHA, v2 checkbox or v3 invisible (see below).
    | hcaptcha  hCaptcha.
    |
    | A provider FAILS CLOSED: with both keys set, a network error, a timeout
    | or an unreadable answer refuses the submission. With a key missing, it
    | refuses everything in production, and in any other environment falls
    | back to the built-in checks with a warning in the log.
    |
    */

    'driver' => env('CAPTCHA_DRIVER', 'builtin'),

    /*
    | The action a provider must report (Turnstile and reCAPTCHA v3 return one).
    | A route can name its own: `captcha:signup`, or `new Captcha('signup')`.
    */
    'action' => null,

    /*
    | Hostnames a provider may report the token was solved on. Null means the
    | host of the request being verified.
    */
    'hostnames' => null,

    /* Seconds. A provider that does not answer in time is a refusal. */
    'timeout' => 3.0,
    'connect_timeout' => 2.0,

    /* The validation error key the middleware throws under. */
    'error_key' => 'captcha',

    /*
    | Field names, shared with @particle-academy/fancy-captcha-ui (which reads
    | them from the props, so renaming here renames there). The honeypot is
    | named to look like a real field: form-filling bots fill what looks real.
    */
    'fields' => [
        'honeypot' => FancyCaptcha\Fields::HONEYPOT,
        'started' => FancyCaptcha\Fields::STARTED,
        'pow' => FancyCaptcha\Fields::POW,
        'token' => FancyCaptcha\Fields::TOKEN,
    ],

    'builtin' => [
        /* Faster than any person fills in a form. */
        'min_seconds' => 3,
        /* A rendered form older than this has to be reloaded. */
        'max_seconds' => 60 * 60 * 6,
        /* Also run the honeypot and timing in front of a provider. */
        'with_providers' => true,
    ],

    'pow' => [
        'enabled' => (bool) env('CAPTCHA_POW', false),
        /*
        | Leading zero bits of SHA-256, 8..32. Each bit doubles the expected
        | work: 18 is about 262,000 hashes, a fraction of a second in a Web
        | Worker on a laptop and a few seconds on an old phone.
        */
        'difficulty' => 18,
        /* Seconds a challenge stays redeemable. */
        'ttl' => 300,
        /* Null for the default store. Must support atomic add() for strict single-use under concurrency. */
        'store' => null,
    ],

    'providers' => [
        'turnstile' => [
            'site_key' => env('TURNSTILE_SITE_KEY'),
            'secret_key' => env('TURNSTILE_SECRET_KEY'),
            'endpoint' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            /* Cloudflare documents tokens of at most 2048 characters. */
            'max_token_length' => 2048,
        ],
        'recaptcha' => [
            'site_key' => env('RECAPTCHA_SITE_KEY'),
            'secret_key' => env('RECAPTCHA_SECRET_KEY'),
            /* v2 (checkbox) or v3 (invisible, scored). */
            'version' => env('RECAPTCHA_VERSION', 'v2'),
            /* v3 only: 0.0 is a bot, 1.0 a person. */
            'score_threshold' => 0.5,
            'endpoint' => 'https://www.google.com/recaptcha/api/siteverify',
            'max_token_length' => 4096,
        ],
        'hcaptcha' => [
            'site_key' => env('HCAPTCHA_SITE_KEY'),
            'secret_key' => env('HCAPTCHA_SECRET_KEY'),
            /* Enterprise only: refuse a risk score ABOVE this (0.0 safe, 1.0 bot). Null to ignore. */
            'score_threshold' => null,
            'endpoint' => 'https://api.hcaptcha.com/siteverify',
            'max_token_length' => 8192,
        ],
    ],

    /*
    | Gate the provider behind a fancy-compliance consent category. When the
    | category is not granted (or fancy-compliance is not installed), the
    | built-in checks run instead, and with proof-of-work unless turned off:
    | refusing consent must not be the cheap way past the check.
    */
    'consent' => [
        'category' => null,
        'fallback_pow' => true,
    ],

    'routes' => [
        'enabled' => true,
        'prefix' => 'fancy-captcha',
        /* Extra middleware for the challenge route. */
        'middleware' => [],
        /* Challenges issued per minute per client IP. */
        'per_minute' => 30,
    ],

    'inertia' => [
        'share' => true,
        'key' => 'fancyCaptcha',
    ],

    'log' => [
        /* Null for the default channel. */
        'channel' => null,
        /* Include the client IP in refusal logs. Off: it is personal data. */
        'ip' => false,
    ],
];
