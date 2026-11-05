<?php

declare(strict_types=1);

use FancyCaptcha\InvalidCaptchaConfiguration;
use FancyCaptcha\Support\ProofOfWork;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;

function powService(): ProofOfWork
{
    return app(ProofOfWork::class);
}

it('counts leading zero bits', function (string $hex, int $bits): void {
    expect(ProofOfWork::leadingZeroBits(hex2bin($hex)))->toBe($bits);
})->with([
    ['ff00', 0],
    ['7f00', 1],
    ['0100', 7],
    ['0080', 8],
    ['0001', 15],
    ['0000', 16],
    ['00000fff', 20],
]);

it('issues a random, short-lived challenge with the configured difficulty', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 12, 'fancy-captcha.pow.ttl' => 120]);

    $a = powService()->issue();
    $b = powService()->issue();

    expect($a['id'])->toMatch('/^[A-Za-z0-9_-]{22}$/')
        ->and($a['id'])->not->toBe($b['id'])
        ->and($a['difficulty'])->toBe(12)
        ->and($a['expiresIn'])->toBe(120)
        ->and($a['algorithm'])->toBe('sha256-leading-zero-bits');
});

it('accepts a correct solution once', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 8]);
    $challenge = powService()->issue();

    expect(powService()->redeem(solvePow($challenge['id'], 8)))->toBeNull();
});

it('never accepts the same challenge twice (replay)', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 8]);
    $solution = solvePow(powService()->issue()['id'], 8);

    expect(powService()->redeem($solution))->toBeNull()
        ->and(powService()->redeem($solution))->not->toBeNull();
});

it('refuses a second redemption even if the challenge entry were still readable (concurrent requests)', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 8]);
    $challenge = powService()->issue();
    // Another request already marked it spent between our read and our write.
    Cache::add('fancy-captcha:pow-spent:'.$challenge['id'], true, 300);

    expect(powService()->redeem(solvePow($challenge['id'], 8)))->toBe('pow_replayed');
});

it('burns a challenge on a wrong answer, so it cannot be retried', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 8]);
    $id = powService()->issue()['id'];

    expect(powService()->redeem(wrongPow($id, 8)))->toBe('pow_insufficient')
        ->and(powService()->redeem(solvePow($id, 8)))->not->toBeNull();
});

it('refuses a solution for a challenge it never issued', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 8]);

    expect(powService()->redeem(solvePow(str_repeat('A', 22), 8)))->toBe('pow_unknown');
});

it('expires a challenge after its ttl', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 8, 'fancy-captcha.pow.ttl' => 60]);
    $solution = solvePow(powService()->issue()['id'], 8);

    Carbon::setTestNow(Carbon::now()->addSeconds(61));

    expect(powService()->redeem($solution))->toBe('pow_unknown');
});

it('uses the difficulty stored with the challenge, not the one in the request', function (): void {
    captchaApp(['fancy-captcha.pow.difficulty' => 16]);
    $id = powService()->issue()['id'];

    // A nonce good for 4 bits but not for 16.
    $weak = null;
    for ($n = 0; $weak === null; $n++) {
        $bits = ProofOfWork::leadingZeroBits(hash('sha256', $id.':'.$n, true));
        if ($bits >= 4 && $bits < 16) {
            $weak = $id.':'.$n;
        }
    }

    expect(powService()->redeem($weak))->toBe('pow_insufficient');
});

it('rejects hostile shapes before touching the cache', function (mixed $input, string $reason): void {
    captchaApp();

    expect(powService()->redeem($input))->toBe($reason);
})->with([
    'missing' => [null, 'pow_missing'],
    'empty' => ['', 'pow_missing'],
    'array' => [['a', 'b'], 'pow_invalid'],
    'no separator' => [str_repeat('A', 22), 'pow_invalid'],
    'short id' => ['abc:1', 'pow_invalid'],
    'bad id alphabet' => [str_repeat('*', 22).':1', 'pow_invalid'],
    'non-digit nonce' => [str_repeat('A', 22).':1e9', 'pow_invalid'],
    'negative nonce' => [str_repeat('A', 22).':-1', 'pow_invalid'],
    'long nonce' => [str_repeat('A', 22).':'.str_repeat('9', 17), 'pow_invalid'],
    'cache key injection' => ['../../etc:passwd:1', 'pow_invalid'],
    'huge' => [str_repeat('A', 1_000_000), 'pow_invalid'],
]);

it('refuses a difficulty outside 8..32 bits', function (int $difficulty): void {
    captchaApp(['fancy-captcha.pow.difficulty' => $difficulty]);

    powService()->issue();
})->with([0, 7, 33, 256])->throws(InvalidCaptchaConfiguration::class);
