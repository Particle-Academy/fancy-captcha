<?php

declare(strict_types=1);

use FancyCaptcha\Fields;
use FancyCompliance\Contracts\ConsentGate;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

function bindConsent(bool $allows, ?array &$asked = null): void
{
    $asked = [];
    app()->instance(ConsentGate::class, new class($allows, $asked) implements ConsentGate
    {
        public function __construct(private bool $answer, private array &$asked) {}

        public function allows(string $category, ?Request $request = null): bool
        {
            $this->asked[] = $category;

            return $this->answer;
        }
    });
}

function gatedConfig(): array
{
    return providerConfig('turnstile', ['fancy-captcha.consent.category' => 'functional', 'fancy-captcha.pow.difficulty' => 8]);
}

it('uses the provider when the consent category is granted', function (): void {
    captchaApp(gatedConfig());
    bindConsent(true, $asked);
    Http::preventStrayRequests();
    Http::fake(['https://challenges.cloudflare.com/*' => Http::response(['success' => true, 'hostname' => 'forms.example.test'])]);

    $verdict = captcha()->verify(submission(humanInput([Fields::TOKEN => 'tok'])));

    expect($verdict->passed)->toBeTrue()->and($verdict->driver)->toBe('turnstile')->and($asked)->toBe(['functional']);
});

it('falls back to the built-in checks, WITH proof-of-work, when consent is refused', function (): void {
    captchaApp(gatedConfig());
    bindConsent(false);
    Http::preventStrayRequests();
    Http::fake();

    $withoutPow = captcha()->verify(submission(humanInput()));
    expect($withoutPow->passed)->toBeFalse()->and($withoutPow->reason)->toBe('pow_missing');

    $id = captcha()->issueChallenge()['id'];
    $verdict = captcha()->verify(submission(humanInput([Fields::POW => solvePow($id, 8)])));

    expect($verdict->passed)->toBeTrue()->and($verdict->driver)->toBe('builtin');
    Http::assertNothingSent();
});

it('can fall back without proof-of-work if the host turns that off', function (): void {
    captchaApp([...gatedConfig(), 'fancy-captcha.consent.fallback_pow' => false]);
    bindConsent(false);

    expect(captcha()->verify(submission(humanInput()))->passed)->toBeTrue();
});

it('treats a gated provider as refused when fancy-compliance is not installed or bound', function (): void {
    captchaApp(gatedConfig());
    Http::preventStrayRequests();
    Http::fake();

    expect(captcha()->verify(submission(humanInput()))->reason)->toBe('pow_missing');
    Http::assertNothingSent();
});

it('asks nothing about consent when no category is configured', function (): void {
    captchaApp(providerConfig('turnstile'));
    bindConsent(false, $asked);
    Http::preventStrayRequests();
    Http::fake(['https://challenges.cloudflare.com/*' => Http::response(['success' => true])]);

    expect(captcha()->verify(submission(humanInput([Fields::TOKEN => 'tok'])))->driver)->toBe('turnstile')
        ->and($asked)->toBe([]);
});

it('tells the UI the consent category, and offers proof-of-work for the fallback', function (): void {
    captchaApp(gatedConfig());

    $props = captcha()->props();

    expect($props['provider'])->toBe('turnstile')
        ->and($props['consentCategory'])->toBe('functional')
        ->and($props['pow']['enabled'])->toBeTrue();
});
