<?php

declare(strict_types=1);

namespace FancyCaptcha\Drivers;

use FancyCaptcha\Contracts\Verifier;
use FancyCaptcha\Verdict;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Request;
use Throwable;

/**
 * The shared shape of Turnstile, reCAPTCHA and hCaptcha: POST the token to a
 * `siteverify` endpoint as a form, read back JSON with `success`, `hostname`
 * and (sometimes) `action`. Plain HTTP through Laravel's client: no SDK.
 *
 * FAILS CLOSED. Every path that is not a positive, well-formed confirmation
 * is a refusal: a thrown exception of any kind (connection, DNS, TLS,
 * timeout), a non-2xx status, a body that is not a JSON object, or a
 * `success` that is anything but boolean true. An outage must not be the
 * way in.
 *
 * Nothing the request or the provider sent is put in the Verdict as text:
 * only fixed reason codes, the HTTP status, and provider error codes that
 * match the documented `lower-case-with-dashes` shape. A provider echoing a
 * token back in an error cannot get it into the log.
 */
abstract class SiteverifyVerifier implements Verifier
{
    /** Bytes of response body read as JSON at most. A siteverify answer is a few hundred. */
    private const MAX_BODY = 16384;

    private const TOKEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.:+/=';

    /**
     * @param  array<string, mixed>  $config  this provider's `fancy-captcha.providers.<name>` block
     * @param  list<string>|null  $hostnames
     */
    public function __construct(
        protected readonly array $config,
        private readonly Http $http,
        private readonly string $tokenField,
        private readonly ?array $hostnames,
        private readonly float $timeout,
        private readonly float $connectTimeout,
        private readonly ?string $defaultAction,
    ) {}

    abstract public function name(): string;

    /** The field the provider's own widget posts, read when the shared field is absent. */
    abstract protected function nativeField(): string;

    /** @return array<string, string> extra form fields for the siteverify call */
    protected function extraPayload(): array
    {
        return [];
    }

    /**
     * Provider-specific checks on a successful answer (scores, required actions).
     *
     * @param  array<string, mixed>  $answer
     */
    protected function inspect(array $answer, ?string $action): ?Verdict
    {
        return null;
    }

    public function verify(Request $request, ?string $action = null): Verdict
    {
        $action ??= $this->defaultAction;
        $token = $request->input($this->tokenField);
        if ($token === null || $token === '') {
            $token = $request->input($this->nativeField());
        }
        if ($token === null || $token === '') {
            return $this->fail('token_missing');
        }
        if (! $this->wellFormed($token)) {
            return $this->fail('token_invalid');
        }

        try {
            $response = $this->http
                ->asForm()
                ->acceptJson()
                ->timeout($this->timeout)
                ->connectTimeout($this->connectTimeout)
                ->withoutRedirecting()
                ->post((string) $this->config['endpoint'], [
                    'secret' => (string) $this->config['secret_key'],
                    'response' => $token,
                    'remoteip' => (string) $request->ip(),
                    ...$this->extraPayload(),
                ]);
        } catch (Throwable $e) {
            // The class only. An exception message can carry the request body.
            return $this->fail('provider_unreachable', ['exception' => $e::class]);
        }

        if ($response->status() < 200 || $response->status() > 299) {
            return $this->fail('provider_http_error', ['status' => $response->status()]);
        }
        $body = $response->body();
        $answer = strlen($body) > self::MAX_BODY ? null : json_decode($body, true, 8);
        if (! is_array($answer) || array_is_list($answer) && $answer !== []) {
            return $this->fail('provider_bad_response');
        }
        if (($answer['success'] ?? null) !== true) {
            return $this->fail('provider_rejected', ['codes' => $this->errorCodes($answer['error-codes'] ?? null)]);
        }

        if (array_key_exists('hostname', $answer) && $answer['hostname'] !== null) {
            $allowed = array_map('strtolower', $this->hostnames ?? [$request->getHost()]);
            if (! is_string($answer['hostname']) || ! in_array(strtolower($answer['hostname']), $allowed, true)) {
                return $this->fail('hostname_mismatch');
            }
        }
        if ($action !== null && isset($answer['action']) && $answer['action'] !== $action) {
            return $this->fail('action_mismatch');
        }

        return $this->inspect($answer, $action) ?? Verdict::pass($this->name());
    }

    /** @param array<string, int|float|string|bool|list<string>> $details */
    protected function fail(string $reason, array $details = []): Verdict
    {
        return Verdict::fail($this->name(), $reason, $details);
    }

    /** Bounded and charset-checked with strspn: linear, no regular expression. */
    private function wellFormed(mixed $token): bool
    {
        $max = (int) ($this->config['max_token_length'] ?? 2048);

        return is_string($token)
            && strlen($token) <= $max
            && strspn($token, self::TOKEN_ALPHABET) === strlen($token);
    }

    /** @return list<string> at most five codes, only of the documented shape */
    private function errorCodes(mixed $codes): array
    {
        if (! is_array($codes)) {
            return [];
        }
        $safe = [];
        foreach (array_slice(array_values($codes), 0, 5) as $code) {
            if (is_string($code) && strlen($code) <= 64 && $code !== ''
                && strspn($code, 'abcdefghijklmnopqrstuvwxyz0123456789-') === strlen($code)) {
                $safe[] = $code;
            }
        }

        return $safe;
    }
}
