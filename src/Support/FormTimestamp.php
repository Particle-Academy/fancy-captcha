<?php

declare(strict_types=1);

namespace FancyCaptcha\Support;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Support\Carbon;

/**
 * The time a form was rendered, signed so it cannot be moved.
 *
 * Format: `<unix seconds>.<base64url HMAC-SHA256>`, 54 characters today.
 *
 * SIGNED, NOT ENCRYPTED, and that is a decision. The value is not a secret:
 * the visitor knows when they loaded the page. What matters is that it cannot
 * be forged backwards to pass the minimum age, or forwards to dodge the
 * maximum, and integrity is exactly what an HMAC gives. Against encryption:
 *
 *  - Laravel's encrypted payload is a base64 JSON blob of about 200 bytes that
 *    must be decoded and JSON-parsed BEFORE it can be authenticated. An HMAC
 *    check reads nothing but a length, two digit runs and 43 characters.
 *  - Verification here is one hash_equals over fixed-length strings, with no
 *    regular expression anywhere, so hostile input cannot make it slow.
 *  - Encryption would hide nothing worth hiding.
 *
 * The key is DERIVED from APP_KEY for this one purpose, so a MAC issued here
 * can never be confused with any other value the app signs with APP_KEY.
 * Rotating APP_KEY invalidates open forms, which is the right outcome.
 */
final class FormTimestamp
{
    /** Longest token accepted, checked before anything else is read. */
    private const MAX_LENGTH = 64;

    /** Seconds a timestamp may be ahead of the clock (multi-server skew). */
    private const SKEW = 2;

    private const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    public function __construct(private readonly Encrypter $encrypter) {}

    public function issue(): string
    {
        $now = (string) Carbon::now()->getTimestamp();

        return $now.'.'.$this->mac($now);
    }

    /** Seconds since the form was rendered, or null when the value is not one we issued. */
    public function age(mixed $token): ?int
    {
        if (! is_string($token) || $token === '' || strlen($token) > self::MAX_LENGTH) {
            return null;
        }
        $dot = strpos($token, '.');
        if ($dot === false) {
            return null;
        }
        $issued = substr($token, 0, $dot);
        $mac = substr($token, $dot + 1);
        if (strlen($issued) < 9 || strlen($issued) > 11 || strspn($issued, '0123456789') !== strlen($issued)) {
            return null;
        }
        if (strlen($mac) !== 43 || strspn($mac, self::B64URL) !== 43) {
            return null;
        }
        if (! hash_equals($this->mac($issued), $mac)) {
            return null;
        }
        $age = Carbon::now()->getTimestamp() - (int) $issued;

        return $age < -self::SKEW ? null : max(0, $age);
    }

    private function mac(string $issued): string
    {
        $key = hash_hmac('sha256', 'fancy-captcha/form-timestamp/v1', $this->encrypter->getKey(), true);

        return rtrim(strtr(base64_encode(hash_hmac('sha256', $issued, $key, true)), '+/', '-_'), '=');
    }
}
