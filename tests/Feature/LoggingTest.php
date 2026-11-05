<?php

declare(strict_types=1);

use FancyCaptcha\Fields;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

it('logs the specific reason for a refusal', function (): void {
    captchaApp();

    captcha()->verify(submission(humanInput(age: 1)), 'signup');

    $record = collect(captchaLogs())->firstWhere('message', 'fancy-captcha refused a submission.');
    expect($record)->not->toBeNull()
        ->and($record['level'])->toBe('info')
        ->and($record['context'])->toMatchArray(['driver' => 'builtin', 'reason' => 'too_fast', 'action' => 'signup', 'route' => 'signup']);
});

it('does not log a pass', function (): void {
    captchaApp();

    captcha()->verify(submission(humanInput()));

    expect(captchaLogs())->toBe([]);
});

it('does not log the IP address unless the host asks for it', function (): void {
    captchaApp();
    captcha()->verify(submission(humanInput(age: 1)));
    expect(allLogText())->not->toContain('203.0.113.7');

    captchaApp(['fancy-captcha.log.ip' => true]);
    captcha()->verify(submission(humanInput(age: 1)));
    expect(allLogText())->toContain('203.0.113.7');
});

it('never logs a token value, on any refusal path', function (Closure|array $response, int $status): void {
    captchaApp(providerConfig('turnstile'));
    Http::preventStrayRequests();
    Http::fake(['https://challenges.cloudflare.com/*' => $response instanceof Closure ? $response : Http::response($response, $status)]);

    $verdict = captcha()->verify(submission(humanInput([Fields::TOKEN => CANARY_TOKEN])), 'signup');

    expect($verdict->passed)->toBeFalse()
        ->and(captchaLogs())->not->toBe([])
        ->and(allLogText())->not->toContain(CANARY_TOKEN)
        ->and(allLogText())->not->toContain('CANARY')
        ->and(allLogText())->not->toContain('secret-key-private');
})->with([
    'provider refused' => [['success' => false, 'error-codes' => ['invalid-input-response']], 200],
    'provider echoes the token in an error' => [['success' => false, 'error-codes' => [CANARY_TOKEN]], 200],
    'network error naming the token' => [fn () => throw new ConnectionException('failed while sending response='.CANARY_TOKEN), 200],
    'http error' => [['token' => CANARY_TOKEN], 500],
    'hostname mismatch' => [['success' => true, 'hostname' => CANARY_TOKEN], 200],
    'action mismatch' => [['success' => true, 'hostname' => 'forms.example.test', 'action' => CANARY_TOKEN], 200],
]);

it('never logs a proof-of-work solution or a form timestamp', function (): void {
    captchaApp(['fancy-captcha.pow.enabled' => true, 'fancy-captcha.pow.difficulty' => 8]);
    $solution = wrongPow(captcha()->issueChallenge()['id'], 8);
    $input = humanInput([Fields::POW => $solution]);

    captcha()->verify(submission($input));

    expect(captchaLogs())->not->toBe([])
        ->and(allLogText())->not->toContain($solution)
        ->and(allLogText())->not->toContain(explode(':', $solution)[0])
        ->and(allLogText())->not->toContain($input[Fields::STARTED]);
});

it('tells the visitor nothing specific', function (): void {
    captchaApp();

    expect(captcha()->failureMessage())->toBe('We could not verify this submission. Please reload the page and try again.')
        ->and(captcha()->failureMessage())->not->toContain('honeypot')
        ->and(captcha()->failureMessage())->not->toContain('fast');
});

it('writes to the configured log channel', function (): void {
    captchaApp([
        'logging.channels.captcha' => ['driver' => 'monolog', 'handler' => Monolog\Handler\NullHandler::class],
        'fancy-captcha.log.channel' => 'captcha',
    ]);

    captcha()->verify(submission(humanInput(age: 1)));

    expect(captchaLogs())->toHaveCount(1);
});
