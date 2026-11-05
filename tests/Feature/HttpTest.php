<?php

declare(strict_types=1);

use FancyCaptcha\Fields;
use FancyCaptcha\Support\FormTimestamp;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;

function dispatchRequest(string $method, string $uri, array $input = []): Symfony\Component\HttpFoundation\Response
{
    return app('router')->dispatch(submission($input, $method, 'https://forms.example.test'.$uri));
}

it('issues a proof-of-work challenge over GET, uncached', function (): void {
    captchaApp(['fancy-captcha.pow.enabled' => true, 'fancy-captcha.pow.difficulty' => 10]);

    $response = dispatchRequest('GET', '/fancy-captcha/challenge');
    $body = json_decode((string) $response->getContent(), true);

    expect($response->getStatusCode())->toBe(200)
        ->and($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and(array_keys($body))->toBe(['id', 'difficulty', 'expiresIn', 'algorithm'])
        ->and($body['difficulty'])->toBe(10);

    expect(captcha()->verify(submission(humanInput([Fields::POW => solvePow($body['id'], 10)])))->passed)->toBeTrue();
});

it('throttles challenge issuance per client by default', function (): void {
    captchaApp(['fancy-captcha.routes.per_minute' => 3]);

    $codes = [];
    for ($i = 0; $i < 4; $i++) {
        try {
            $codes[] = dispatchRequest('GET', '/fancy-captcha/challenge')->getStatusCode();
        } catch (Illuminate\Http\Exceptions\ThrottleRequestsException $e) {
            $codes[] = $e->getStatusCode();
        }
    }

    expect($codes)->toBe([200, 200, 200, 429]);
});

it('can move or switch off the routes', function (): void {
    captchaApp(['fancy-captcha.routes.prefix' => 'bots']);
    expect(dispatchRequest('GET', '/bots/challenge')->getStatusCode())->toBe(200);

    captchaApp(['fancy-captcha.routes.enabled' => false]);
    expect(app('router')->getRoutes()->getByName('fancy-captcha.challenge'))->toBeNull();
});

it('guards a route with the captcha middleware and its action', function (): void {
    captchaApp();
    Route::post('/signup', fn () => 'created')->middleware('captcha:signup');

    expect(dispatchRequest('POST', '/signup', humanInput())->getContent())->toBe('created');

    captchaApp();
    Route::post('/signup', fn () => 'created')->middleware('captcha:signup');
    try {
        dispatchRequest('POST', '/signup', humanInput(age: 0));
        $this->fail('expected a ValidationException');
    } catch (ValidationException $e) {
        expect($e->errors())->toBe(['captcha' => ['We could not verify this submission. Please reload the page and try again.']]);
    }
});

it('lets safe methods through the middleware untouched', function (): void {
    captchaApp();
    Route::get('/signup', fn () => 'form')->middleware('captcha');

    expect(dispatchRequest('GET', '/signup')->getContent())->toBe('form')
        ->and(captchaLogs())->toBe([]);
});

it('puts the error under the configured key', function (): void {
    captchaApp(['fancy-captcha.error_key' => 'form']);
    Route::post('/signup', fn () => 'created')->middleware('captcha');

    expect(fn () => dispatchRequest('POST', '/signup', ['x' => 1]))->toThrow(function (ValidationException $e): void {
        expect(array_keys($e->errors()))->toBe(['form']);
    });
});

it('gives the UI its props: fields, a fresh signed timestamp, and no secrets', function (): void {
    captchaApp(providerConfig('turnstile', ['fancy-captcha.action' => 'signup']));

    $props = captcha()->props();

    expect(array_keys($props))->toBe(['provider', 'siteKey', 'action', 'fields', 'started', 'pow', 'consentCategory', 'configured'])
        ->and($props['provider'])->toBe('turnstile')
        ->and($props['siteKey'])->toBe('site-key-public')
        ->and($props['action'])->toBe('signup')
        ->and($props['fields'])->toBe(['honeypot' => 'contact_fax', 'started' => '_captcha_started', 'pow' => '_captcha_pow', 'token' => '_captcha_token'])
        ->and(app(FormTimestamp::class)->age($props['started']))->toBe(0)
        ->and($props['pow'])->toBe(['enabled' => false, 'difficulty' => 18, 'challengeUrl' => '/fancy-captcha/challenge'])
        ->and($props['configured'])->toBeTrue()
        ->and(json_encode($props))->not->toContain('secret-key-private');
});

it('names the provider the way the UI does', function (array $config, string $provider): void {
    captchaApp($config);

    expect(captcha()->props()['provider'])->toBe($provider);
})->with([
    [[], 'builtin'],
    [providerConfig('recaptcha', ['fancy-captcha.providers.recaptcha.version' => 'v2']), 'recaptcha-v2'],
    [providerConfig('recaptcha', ['fancy-captcha.providers.recaptcha.version' => 'v3']), 'recaptcha-v3'],
    [providerConfig('hcaptcha'), 'hcaptcha'],
]);

it('reports a keyless provider as unconfigured, and in local hands the UI the built-in mode', function (): void {
    captchaApp(['fancy-captcha.driver' => 'turnstile'], 'local');
    $props = captcha()->props();
    expect($props['configured'])->toBeFalse()->and($props['provider'])->toBe('builtin')->and($props['siteKey'])->toBeNull();

    captchaApp(['fancy-captcha.driver' => 'turnstile'], 'production');
    $props = captcha()->props();
    expect($props['configured'])->toBeFalse()->and($props['provider'])->toBe('turnstile')->and($props['siteKey'])->toBeNull();
});

it('honours renamed fields end to end', function (): void {
    captchaApp(['fancy-captcha.fields.honeypot' => 'office_fax']);

    expect(captcha()->props()['fields']['honeypot'])->toBe('office_fax')
        ->and(captcha()->verify(submission([...humanInput(), 'office_fax' => 'x']))->reason)->toBe('honeypot_filled');
});

it('shares the props with Inertia when Inertia is installed', function (): void {
    captchaApp();

    expect(Inertia\Inertia::$shared)->toHaveKey('fancyCaptcha')
        ->and((Inertia\Inertia::$shared['fancyCaptcha'])()['provider'])->toBe('builtin');
});
