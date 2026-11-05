<?php

declare(strict_types=1);

use FancyCaptcha\Facades\Captcha;
use FancyCaptcha\Rules\Captcha as CaptchaRule;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use PHPUnit\Framework\AssertionFailedError;

it('passes everything when faked to pass, without any real check', function (): void {
    captchaApp(providerConfig('turnstile'));
    Http::preventStrayRequests();
    Http::fake();
    $fake = Captcha::fake();

    expect(captcha()->verify(submission(['nothing' => 'here']))->passed)->toBeTrue();
    $fake->assertVerified();
    Http::assertNothingSent();
});

it('fails everything when faked to fail', function (): void {
    captchaApp();
    Captcha::fake(passes: false);
    submission(humanInput());

    expect(Validator::make([], ['captcha' => [new CaptchaRule]])->fails())->toBeTrue();
});

it('can be switched between pass and fail mid-test', function (): void {
    captchaApp();
    $fake = Captcha::fake()->fails();
    expect(captcha()->verify(submission())->passed)->toBeFalse();

    $fake->passes();
    expect(captcha()->verify(submission())->passed)->toBeTrue();
});

it('records what was verified, by action', function (): void {
    captchaApp();
    $fake = Captcha::fake();
    Route::post('/signup', fn () => 'ok')->middleware('captcha:signup');
    app('router')->dispatch(submission([], 'POST', 'https://forms.example.test/signup'));

    $fake->assertVerified('signup');
    $fake->assertVerifiedCount(1);
    expect(fn () => $fake->assertVerified('login'))->toThrow(AssertionFailedError::class);
    expect(fn () => $fake->assertNotVerified())->toThrow(AssertionFailedError::class);
});

it('asserts nothing was verified', function (): void {
    captchaApp();
    $fake = Captcha::fake();

    $fake->assertNotVerified();
    expect(fn () => $fake->assertVerified())->toThrow(AssertionFailedError::class);
});

it('refuses to fake in production, where it would be a bypass', function (): void {
    captchaApp([], 'production');

    Captcha::fake();
})->throws(LogicException::class);
