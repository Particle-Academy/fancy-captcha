<?php

declare(strict_types=1);

namespace FancyCaptcha;

/**
 * Default form field names, shared with @particle-academy/fancy-captcha-ui's
 * `CAPTCHA_FIELDS`. A host renames them in `fancy-captcha.fields`; the UI then
 * takes the names from the props, so the two sides cannot disagree.
 */
final class Fields
{
    /** The honeypot. Named like a real field, because form-filling bots fill what looks real. */
    public const HONEYPOT = 'contact_fax';

    /** The signed time the form was rendered. */
    public const STARTED = '_captcha_started';

    /** `<challenge id>:<nonce>`, the proof-of-work solution. */
    public const POW = '_captcha_pow';

    /** A provider token (Turnstile, reCAPTCHA, hCaptcha). */
    public const TOKEN = '_captcha_token';

    /** @return array{honeypot: string, started: string, pow: string, token: string} */
    public static function resolve(array $configured): array
    {
        $fields = [];
        foreach (['honeypot' => self::HONEYPOT, 'started' => self::STARTED, 'pow' => self::POW, 'token' => self::TOKEN] as $key => $default) {
            $name = $configured[$key] ?? $default;
            if (! is_string($name) || preg_match('/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/', $name) !== 1) {
                throw new InvalidCaptchaConfiguration("fancy-captcha.fields.{$key} must be a plain field name.");
            }
            $fields[$key] = $name;
        }
        if (count(array_unique($fields)) !== 4) {
            throw new InvalidCaptchaConfiguration('fancy-captcha.fields must name four different fields.');
        }

        return $fields;
    }
}
