<?php

declare(strict_types=1);

use FancyCaptcha\Fields;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\Http;

const ENDPOINTS = [
    'turnstile' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    'recaptcha' => 'https://www.google.com/recaptcha/api/siteverify',
    'hcaptcha' => 'https://api.hcaptcha.com/siteverify',
];

function providerFixture(string $name, array $merge = []): array
{
    return [...json_decode((string) file_get_contents(__DIR__.'/../Fixtures/'.$name.'.json'), true, 16, JSON_THROW_ON_ERROR), ...$merge];
}

/** Fakes ONE provider endpoint and forbids every other request. */
function fakeProvider(string $driver, array|Closure $response, int $status = 200): void
{
    Http::preventStrayRequests();
    Http::fake([ENDPOINTS[$driver] => $response instanceof Closure ? $response : Http::response($response, $status)]);
}

function tokenInput(array $extra = []): array
{
    return humanInput([Fields::TOKEN => 'XXXX.DUMMY.TOKEN.XXXX', ...$extra]);
}

/**
 * A broken provider, by name. Datasets name the failure rather than holding a
 * closure, because Pest INVOKES closures it finds in a dataset.
 */
function brokenProvider(string $kind, string $token = ''): Closure
{
    return match ($kind) {
        'connection refused' => fn () => throw new ConnectionException('cURL error 7: Failed to connect, response='.$token),
        'timeout' => fn () => throw new ConnectionException('cURL error 28: Operation timed out after 3001 milliseconds'),
        'any other exception' => fn () => throw new RuntimeException('boom '.$token),
        'http 500' => fn () => Http::response(['success' => true, 'echo' => $token], 500),
        'http 302' => fn () => Http::response(['success' => true], 302, ['Location' => 'https://evil.example/']),
        'not json' => fn () => Http::response('<html>Bad gateway</html>', 200),
        'json scalar' => fn () => Http::response('true', 200),
        'huge body' => fn () => Http::response('{"success":true,"pad":"'.str_repeat('a', 20000).'"}', 200),
    };
}

it('passes a valid provider response and sends the documented form fields', function (string $driver, string $fixture, array $config): void {
    captchaApp(providerConfig($driver, $config));
    fakeProvider($driver, providerFixture($fixture));

    $verdict = captcha()->verify(submission(tokenInput()), 'signup');

    expect($verdict->reason)->toBeNull()->and($verdict->passed)->toBeTrue()->and($verdict->driver)->toBe($driver);
    Http::assertSent(fn (ClientRequest $r): bool => $r->url() === ENDPOINTS[$driver]
        && $r->method() === 'POST'
        && $r->isForm()
        && $r['secret'] === 'secret-key-private'
        && $r['response'] === 'XXXX.DUMMY.TOKEN.XXXX'
        && $r['remoteip'] === '203.0.113.7');
})->with([
    'turnstile' => ['turnstile', 'turnstile-success', []],
    'recaptcha v2' => ['recaptcha', 'recaptcha-v2-success', ['fancy-captcha.providers.recaptcha.version' => 'v2']],
    'recaptcha v3' => ['recaptcha', 'recaptcha-v3-success', ['fancy-captcha.providers.recaptcha.version' => 'v3']],
    'hcaptcha' => ['hcaptcha', 'hcaptcha-success', []],
]);

it('sends the site key to hCaptcha, as hCaptcha recommends', function (): void {
    captchaApp(providerConfig('hcaptcha'));
    fakeProvider('hcaptcha', providerFixture('hcaptcha-success'));

    captcha()->verify(submission(tokenInput()));

    Http::assertSent(fn (ClientRequest $r): bool => $r['sitekey'] === 'site-key-public');
});

it('reads the provider widget\'s own field when the shared one is absent', function (string $driver, string $native, string $fixture): void {
    captchaApp(providerConfig($driver));
    fakeProvider($driver, providerFixture($fixture));

    expect(captcha()->verify(submission(humanInput([$native => 'NATIVE-token'])))->passed)->toBeTrue();
    Http::assertSent(fn (ClientRequest $r): bool => $r['response'] === 'NATIVE-token');
})->with([
    ['turnstile', 'cf-turnstile-response', 'turnstile-success'],
    ['recaptcha', 'g-recaptcha-response', 'recaptcha-v2-success'],
    ['hcaptcha', 'h-captcha-response', 'hcaptcha-success'],
]);

it('refuses what the provider refuses', function (string $driver, string $fixture): void {
    captchaApp(providerConfig($driver));
    fakeProvider($driver, providerFixture($fixture));

    $verdict = captcha()->verify(submission(tokenInput()));

    expect($verdict->passed)->toBeFalse()->and($verdict->reason)->toBe('provider_rejected');
})->with([
    ['turnstile', 'turnstile-failure'],
    ['recaptcha', 'recaptcha-failure'],
    ['hcaptcha', 'hcaptcha-failure'],
]);

it('only accepts boolean true as success', function (mixed $success): void {
    captchaApp(providerConfig('turnstile'));
    fakeProvider('turnstile', providerFixture('turnstile-success', ['success' => $success]));

    expect(captcha()->verify(submission(tokenInput()))->passed)->toBeFalse();
})->with([['true'], [1], [null], [[true]]]);

it('FAILS CLOSED on a network error, a timeout, a server error or a garbled body', function (string $kind, string $reason): void {
    captchaApp(providerConfig('turnstile'));
    fakeProvider('turnstile', brokenProvider($kind));

    $verdict = captcha()->verify(submission(tokenInput()));

    expect($verdict->passed)->toBeFalse()->and($verdict->reason)->toBe($reason);
})->with([
    ['connection refused', 'provider_unreachable'],
    ['timeout', 'provider_unreachable'],
    ['any other exception', 'provider_unreachable'],
    ['http 500', 'provider_http_error'],
    ['http 302', 'provider_http_error'],
    ['not json', 'provider_bad_response'],
    ['json scalar', 'provider_bad_response'],
    ['huge body', 'provider_bad_response'],
]);

it('keeps every default when a host config sets only the keys', function (): void {
    // TestApp sets these BEFORE the provider registers, exactly like a host's
    // partial config/fancy-captcha.php. A shallow merge would drop `endpoint`.
    captchaApp(providerConfig('turnstile'));

    expect(config('fancy-captcha.providers.turnstile.endpoint'))->toBe(ENDPOINTS['turnstile'])
        ->and(config('fancy-captcha.providers.turnstile.max_token_length'))->toBe(2048)
        ->and(config('fancy-captcha.builtin.min_seconds'))->toBe(3);
});

it('sends the configured short timeout', function (): void {
    captchaApp(providerConfig('turnstile', ['fancy-captcha.timeout' => 2.5]));
    $seen = null;
    Http::preventStrayRequests();
    Http::fake(function (ClientRequest $request, array $options) use (&$seen) {
        $seen = $options['timeout'] ?? null;

        return Http::response(providerFixture('turnstile-success'));
    });

    captcha()->verify(submission(tokenInput()));

    expect($seen)->toBe(2.5);
});

it('checks the hostname the provider reports', function (array $config, string $hostname, bool $passes): void {
    captchaApp(providerConfig('turnstile', $config));
    fakeProvider('turnstile', providerFixture('turnstile-success', ['hostname' => $hostname]));

    $verdict = captcha()->verify(submission(tokenInput()));

    expect($verdict->passed)->toBe($passes);
    if (! $passes) {
        expect($verdict->reason)->toBe('hostname_mismatch');
    }
})->with([
    'request host by default' => [[], 'forms.example.test', true],
    'another site by default' => [[], 'evil.example', false],
    'configured list' => [['fancy-captcha.hostnames' => ['www.example.test', 'forms.example.test']], 'www.example.test', true],
    'not in configured list' => [['fancy-captcha.hostnames' => ['www.example.test']], 'forms.example.test', false],
    'case-insensitive' => [[], 'FORMS.Example.Test', true],
]);

it('checks the action the provider reports', function (?string $expected, array $merge, bool $passes): void {
    captchaApp(providerConfig('turnstile'));
    fakeProvider('turnstile', providerFixture('turnstile-success', $merge));

    expect(captcha()->verify(submission(tokenInput()), $expected)->passed)->toBe($passes);
})->with([
    'matches' => ['signup', ['action' => 'signup'], true],
    'differs' => ['signup', ['action' => 'login'], false],
    'none expected' => [null, ['action' => 'login'], true],
    'not reported' => ['signup', ['action' => null], true],
]);

it('enforces the reCAPTCHA v3 score threshold and expected action', function (array $merge, ?string $action, bool $passes, ?string $reason): void {
    captchaApp(providerConfig('recaptcha', ['fancy-captcha.providers.recaptcha.version' => 'v3', 'fancy-captcha.providers.recaptcha.score_threshold' => 0.5]));
    fakeProvider('recaptcha', providerFixture('recaptcha-v3-success', $merge));

    $verdict = captcha()->verify(submission(tokenInput()), $action);

    expect($verdict->passed)->toBe($passes)->and($verdict->reason)->toBe($reason);
})->with([
    'good score' => [['score' => 0.9], 'signup', true, null],
    'at threshold' => [['score' => 0.5], 'signup', true, null],
    'low score' => [['score' => 0.1], 'signup', false, 'score_below_threshold'],
    'no score' => [['score' => null], 'signup', false, 'score_below_threshold'],
    'score as string' => [['score' => '0.9'], 'signup', false, 'score_below_threshold'],
    'wrong action' => [['action' => 'login'], 'signup', false, 'action_mismatch'],
    'missing action, v3 requires it' => [['action' => null], 'signup', false, 'action_mismatch'],
]);

it('refuses a missing or malformed token without calling the provider', function (mixed $token, string $reason): void {
    captchaApp(providerConfig('turnstile'));
    fakeProvider('turnstile', providerFixture('turnstile-success'));

    $verdict = captcha()->verify(submission(humanInput([Fields::TOKEN => $token])));

    expect($verdict->reason)->toBe($reason);
    Http::assertNothingSent();
})->with([
    'missing' => [null, 'token_missing'],
    'empty' => ['', 'token_missing'],
    'array' => [['a'], 'token_invalid'],
    'too long for turnstile (2048)' => [str_repeat('a', 2049), 'token_invalid'],
    'control characters' => ["abc\x00def", 'token_invalid'],
    'spaces' => ['abc def', 'token_invalid'],
    'one megabyte' => [str_repeat('a', 1_000_000), 'token_invalid'],
]);

it('runs the built-in honeypot and timing first, and skips the provider call when they fail', function (): void {
    captchaApp(providerConfig('turnstile'));
    fakeProvider('turnstile', providerFixture('turnstile-success'));

    $verdict = captcha()->verify(submission(tokenInput([Fields::HONEYPOT => 'bot'])));

    expect($verdict->reason)->toBe('honeypot_filled');
    Http::assertNothingSent();
});

it('in production, refuses everything when a provider is selected without keys', function (): void {
    captchaApp(['fancy-captcha.driver' => 'turnstile'], 'production');
    Http::preventStrayRequests();
    Http::fake();

    $verdict = captcha()->verify(submission(tokenInput()));

    expect($verdict->passed)->toBeFalse()->and($verdict->reason)->toBe('provider_unconfigured');
    expect(collect(captchaLogs())->where('level', 'error')->pluck('message')->implode(' '))
        ->toContain('turnstile')->toContain('no site key or secret');
});

it('in local or testing, says clearly that a keyless provider fell back to the built-in checks', function (string $env): void {
    captchaApp(['fancy-captcha.driver' => 'turnstile'], $env);
    Http::preventStrayRequests();
    Http::fake();

    $verdict = captcha()->verify(submission(humanInput()));

    expect($verdict->passed)->toBeTrue()->and($verdict->driver)->toBe('builtin');
    expect(collect(captchaLogs())->where('level', 'warning')->pluck('message')->implode(' '))
        ->toContain('turnstile is selected but has no site key or secret')->toContain('built-in checks only');
    Http::assertNothingSent();
})->with(['local', 'testing']);

it('refuses an unknown driver name', function (): void {
    captchaApp(['fancy-captcha.driver' => 'nope']);

    captcha()->verify(submission(humanInput()));
})->throws(FancyCaptcha\InvalidCaptchaConfiguration::class);
