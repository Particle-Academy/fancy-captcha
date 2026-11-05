<?php

declare(strict_types=1);

use FancyCaptcha\Support\FormTimestamp;
use FancyCaptcha\Tests\Support\TestApp;
use Illuminate\Support\Carbon;

it('issues a timestamp it can read back as an age in seconds', function (): void {
    captchaApp();
    $token = app(FormTimestamp::class)->issue();

    Carbon::setTestNow(Carbon::now()->addSeconds(42));

    expect(app(FormTimestamp::class)->age($token))->toBe(42);
});

it('is signed, not just encoded: the time is readable but cannot be moved', function (): void {
    captchaApp();
    $token = app(FormTimestamp::class)->issue();
    [$issued, $mac] = explode('.', $token);

    expect((int) $issued)->toBe(Carbon::now()->getTimestamp())
        ->and(app(FormTimestamp::class)->age(($issued - 3600).'.'.$mac))->toBeNull()
        ->and(app(FormTimestamp::class)->age($issued.'.'.strrev($mac)))->toBeNull();
});

it('is bound to APP_KEY: a token from another app does not verify', function (): void {
    captchaApp(['app.key' => 'base64:'.base64_encode(str_repeat('z', 32))]);
    $foreign = app(FormTimestamp::class)->issue();

    captchaApp();

    expect(app(FormTimestamp::class)->age($foreign))->toBeNull();
});

it('uses a key derived for this purpose, not APP_KEY itself', function (): void {
    captchaApp();
    $token = app(FormTimestamp::class)->issue();
    [$issued, $mac] = explode('.', $token);
    $raw = base64_decode(substr(TestApp::APP_KEY, 7), true);
    $naive = rtrim(strtr(base64_encode(hash_hmac('sha256', $issued, $raw, true)), '+/', '-_'), '=');

    expect($mac)->not->toBe($naive);
});

it('refuses a timestamp from the future', function (): void {
    captchaApp();
    Carbon::setTestNow(Carbon::now()->addMinutes(5));
    $future = app(FormTimestamp::class)->issue();
    Carbon::setTestNow(Carbon::now()->subMinutes(5));

    expect(app(FormTimestamp::class)->age($future))->toBeNull();
});

it('rejects hostile shapes without throwing', function (mixed $input): void {
    captchaApp();

    expect(app(FormTimestamp::class)->age($input))->toBeNull();
})->with([
    'empty' => [''],
    'null' => [null],
    'array' => [['1762344000', 'mac']],
    'integer' => [1762344000],
    'no dot' => ['1762344000'],
    'three parts' => ['1762344000.abc.def'],
    'signed digits' => ['-1762344000.'.str_repeat('a', 43)],
    'spaces' => [' 1762344000.'.str_repeat('a', 43)],
    'unicode digits' => ["\u{0661}\u{0667}\u{0666}\u{0662}.".str_repeat('a', 43)],
    'short mac' => ['1762344000.abc'],
    'bad alphabet' => ['1762344000.'.str_repeat('*', 43)],
    'one megabyte' => [str_repeat('1', 1_000_000).'.'.str_repeat('a', 43)],
]);

it('stays fast on a huge input (bounded before any parsing)', function (): void {
    captchaApp();
    $hostile = str_repeat('9.', 500_000);

    $start = hrtime(true);
    $result = app(FormTimestamp::class)->age($hostile);
    $ms = (hrtime(true) - $start) / 1e6;

    expect($result)->toBeNull()->and($ms)->toBeLessThan(20);
});
