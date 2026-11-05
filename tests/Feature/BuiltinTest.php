<?php

declare(strict_types=1);

use FancyCaptcha\Fields;
use FancyCaptcha\Rules\Captcha as CaptchaRule;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;

it('is the default driver, with no configuration at all', function (): void {
    captchaApp();

    expect(config('fancy-captcha.driver'))->toBe('builtin')
        ->and(captcha()->verify(submission(humanInput()))->passed)->toBeTrue();
});

it('shares its field names as constants', function (): void {
    expect(Fields::HONEYPOT)->toBe('contact_fax')
        ->and(Fields::STARTED)->toBe('_captcha_started')
        ->and(Fields::POW)->toBe('_captcha_pow')
        ->and(Fields::TOKEN)->toBe('_captcha_token');
});

it('refuses a submission faster than the minimum', function (int $age): void {
    captchaApp();

    $verdict = captcha()->verify(submission(humanInput(age: $age)));

    expect($verdict->passed)->toBeFalse()->and($verdict->reason)->toBe('too_fast');
})->with([0, 1, 2]);

it('accepts exactly at the minimum and refuses past the maximum age', function (): void {
    captchaApp();
    expect(captcha()->verify(submission(humanInput(age: 3)))->passed)->toBeTrue();

    captchaApp();
    $verdict = captcha()->verify(submission(humanInput(age: 6 * 3600 + 1)));
    expect($verdict->passed)->toBeFalse()->and($verdict->reason)->toBe('timestamp_expired');
});

it('takes the minimum and maximum from config', function (): void {
    captchaApp(['fancy-captcha.builtin.min_seconds' => 8, 'fancy-captcha.builtin.max_seconds' => 60]);

    expect(captcha()->verify(submission(humanInput(age: 5)))->reason)->toBe('too_fast');
    captchaApp(['fancy-captcha.builtin.min_seconds' => 8, 'fancy-captcha.builtin.max_seconds' => 60]);
    expect(captcha()->verify(submission(humanInput(age: 61)))->reason)->toBe('timestamp_expired');
});

it('refuses a filled honeypot, whatever was put in it', function (mixed $value): void {
    captchaApp();

    $verdict = captcha()->verify(submission(humanInput([Fields::HONEYPOT => $value])));

    expect($verdict->passed)->toBeFalse()->and($verdict->reason)->toBe('honeypot_filled');
})->with([['555-0100'], [' '], ['0'], [['x']]]);

it('refuses a missing or forged timestamp', function (array $override, string $reason): void {
    captchaApp();
    $input = humanInput();
    unset($input[Fields::STARTED]);

    expect(captcha()->verify(submission([...$input, ...$override]))->reason)->toBe($reason);
})->with([
    'missing' => [[], 'timestamp_missing'],
    'forged' => [[Fields::STARTED => '1762300000.'.str_repeat('A', 43)], 'timestamp_invalid'],
    'array' => [[Fields::STARTED => ['x']], 'timestamp_missing'],
]);

it('requires a solved proof-of-work when it is switched on', function (): void {
    captchaApp(['fancy-captcha.pow.enabled' => true, 'fancy-captcha.pow.difficulty' => 8]);

    expect(captcha()->verify(submission(humanInput()))->reason)->toBe('pow_missing');

    $id = captcha()->issueChallenge()['id'];
    expect(captcha()->verify(submission(humanInput([Fields::POW => solvePow($id, 8)])))->passed)->toBeTrue();
});

it('refuses a proof-of-work replayed on a second submission', function (): void {
    captchaApp(['fancy-captcha.pow.enabled' => true, 'fancy-captcha.pow.difficulty' => 8]);
    $solution = solvePow(captcha()->issueChallenge()['id'], 8);

    $first = captcha()->verify(submission(humanInput([Fields::POW => $solution])));
    $second = captcha()->verify(submission(humanInput([Fields::POW => $solution])));

    expect($first->passed)->toBeTrue()
        ->and($second->passed)->toBeFalse()
        ->and($second->reason)->toBeIn(['pow_unknown', 'pow_replayed']);
});

it('verifies once per request, so the middleware and the rule together do not burn the challenge twice', function (): void {
    captchaApp(['fancy-captcha.pow.enabled' => true, 'fancy-captcha.pow.difficulty' => 8]);
    $request = submission(humanInput([Fields::POW => solvePow(captcha()->issueChallenge()['id'], 8)]));

    expect(captcha()->verify($request)->passed)->toBeTrue()
        ->and(captcha()->verify($request)->passed)->toBeTrue();
});

it('works as a validation rule, with the generic message', function (): void {
    captchaApp();
    submission(humanInput(age: 1));

    $validator = Validator::make(['email' => 'a@example.test'], ['captcha' => [new CaptchaRule]]);

    expect($validator->fails())->toBeTrue()
        ->and($validator->errors()->first('captcha'))->toBe('We could not verify this submission. Please reload the page and try again.');

    captchaApp();
    submission(humanInput());
    expect(Validator::make([], ['captcha' => [new CaptchaRule]])->passes())->toBeTrue();
});

it('makes no network call in built-in mode', function (): void {
    captchaApp();
    Http::preventStrayRequests();
    Http::fake();

    captcha()->verify(submission(humanInput()));

    Http::assertNothingSent();
});
