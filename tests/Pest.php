<?php

declare(strict_types=1);

use FancyCaptcha\CaptchaManager;
use FancyCaptcha\Fields;
use FancyCaptcha\Support\FormTimestamp;
use FancyCaptcha\Tests\Support\TestApp;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Facade;

// Every test boots its own kernel; drop it afterwards so no container, facade,
// cache entry or frozen clock leaks into the next test.
uses()->beforeEach(function (): void {
    Carbon::setTestNow('2026-11-05 12:00:00');
    Inertia\Inertia::$shared = [];
    $GLOBALS['captchaLogs'] = [];
})->afterEach(function (): void {
    Carbon::setTestNow();
    Facade::clearResolvedInstances();
    Container::setInstance(null);
})->in(__DIR__);

/** A canary that must never appear in a log line. */
const CANARY_TOKEN = 'XXXX.CANARY-token-value_must-never-be-logged.XXXX';

function captchaApp(array $config = [], string $env = 'testing'): Application
{
    $app = TestApp::boot($config, $env);
    $app['events']->listen(MessageLogged::class, function (MessageLogged $event): void {
        $GLOBALS['captchaLogs'][] = ['level' => $event->level, 'message' => $event->message, 'context' => $event->context];
    });

    return $app;
}

/** @return list<array{level: string, message: string, context: array}> */
function captchaLogs(): array
{
    return $GLOBALS['captchaLogs'];
}

/** Every log record, flattened to one string, for "is X anywhere in the logs". */
function allLogText(): string
{
    return json_encode(captchaLogs(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

function captcha(): CaptchaManager
{
    return app(CaptchaManager::class);
}

/** A form timestamp issued $secondsAgo seconds before "now". */
function startedAgo(int $secondsAgo): string
{
    Carbon::setTestNow(Carbon::now()->subSeconds($secondsAgo));
    $token = app(FormTimestamp::class)->issue();
    Carbon::setTestNow(Carbon::now()->addSeconds($secondsAgo));

    return $token;
}

/** A form submission, bound as the current request. */
function submission(array $input = [], string $method = 'POST', string $uri = 'https://forms.example.test/signup'): Request
{
    $request = Request::create($uri, $method, $input, [], [], ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_ACCEPT' => 'application/json']);
    app()->instance('request', $request);

    return $request;
}

/** The fields a human's browser would send: empty honeypot, a form rendered a while ago. */
function humanInput(array $extra = [], int $age = 10): array
{
    return [Fields::HONEYPOT => '', Fields::STARTED => startedAgo($age), 'email' => 'ada@example.test', ...$extra];
}

/** Brute-forces a nonce the way the browser worker does. Test difficulties are small. */
function solvePow(string $id, int $difficulty): string
{
    for ($nonce = 0; ; $nonce++) {
        if (FancyCaptcha\Support\ProofOfWork::leadingZeroBits(hash('sha256', $id.':'.$nonce, true)) >= $difficulty) {
            return $id.':'.$nonce;
        }
    }
}

/** A nonce that does NOT meet the difficulty. */
function wrongPow(string $id, int $difficulty): string
{
    for ($nonce = 0; ; $nonce++) {
        if (FancyCaptcha\Support\ProofOfWork::leadingZeroBits(hash('sha256', $id.':'.$nonce, true)) < $difficulty) {
            return $id.':'.$nonce;
        }
    }
}

/** Provider config with both keys set. */
function providerConfig(string $driver, array $extra = []): array
{
    return [
        'fancy-captcha.driver' => $driver,
        "fancy-captcha.providers.{$driver}.site_key" => 'site-key-public',
        "fancy-captcha.providers.{$driver}.secret_key" => 'secret-key-private',
        ...$extra,
    ];
}
