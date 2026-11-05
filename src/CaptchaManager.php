<?php

declare(strict_types=1);

namespace FancyCaptcha;

use Closure;
use FancyCaptcha\Contracts\Verifier;
use FancyCaptcha\Drivers\BuiltinVerifier;
use FancyCaptcha\Drivers\HcaptchaVerifier;
use FancyCaptcha\Drivers\RecaptchaVerifier;
use FancyCaptcha\Drivers\SiteverifyVerifier;
use FancyCaptcha\Drivers\TurnstileVerifier;
use FancyCaptcha\Support\FormTimestamp;
use FancyCaptcha\Support\ProofOfWork;
use FancyCaptcha\Testing\CaptchaFake;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Request;
use LogicException;
use Psr\Log\LoggerInterface;

/**
 * The one entry point: `Captcha::verify($request, 'signup')`.
 *
 * Chooses the driver for THIS request (config, then consent), runs the
 * built-in checks in front of a provider, remembers the verdict on the
 * request so the middleware and the rule together verify once (a second run
 * would find its proof-of-work already spent), and logs every refusal with
 * its reason. The visitor only ever gets failureMessage().
 */
final class CaptchaManager
{
    public const PROVIDERS = ['turnstile', 'recaptcha', 'hcaptcha'];

    private const MEMO = 'fancy-captcha.verdicts';

    /** @var array<string, Closure(Application, array): Verifier> */
    private array $custom = [];

    private ?CaptchaFake $fake = null;

    public function __construct(private readonly Application $app) {}

    public function verify(Request $request, ?string $action = null): Verdict
    {
        $memo = $request->attributes->get(self::MEMO, []);
        $key = $action ?? '';
        if (isset($memo[$key])) {
            return $memo[$key];
        }

        $verdict = $this->fake?->verify($request, $action) ?? $this->decide($request, $action);

        if (! $verdict->passed) {
            $this->logRefusal($request, $action, $verdict);
        }
        $request->attributes->set(self::MEMO, [...$memo, $key => $verdict]);

        return $verdict;
    }

    public function passes(Request $request, ?string $action = null): bool
    {
        return $this->verify($request, $action)->passed;
    }

    /** What the visitor is told. Never the reason. */
    public function failureMessage(): string
    {
        return (string) $this->app->make('translator')->get('fancy-captcha::messages.failed');
    }

    /** @return array{id: string, difficulty: int, expiresIn: int, algorithm: string} */
    public function issueChallenge(): array
    {
        return $this->pow()->issue();
    }

    /**
     * Register a custom driver: `Captcha::extend('friendly', fn ($app, $config) => new FriendlyVerifier(...))`.
     *
     * @param  Closure(Application, array): Verifier  $factory
     */
    public function extend(string $name, Closure $factory): void
    {
        $this->custom[$name] = $factory;
    }

    /**
     * Swap every verification for a fake, in a host's tests. Refused in
     * production, where a fake is a bypass.
     */
    public function fake(bool $passes = true): CaptchaFake
    {
        if ($this->app->environment('production')) {
            throw new LogicException('fancy-captcha: Captcha::fake() is for tests and is refused in production.');
        }

        return $this->fake = new CaptchaFake($passes);
    }

    /**
     * Props for @particle-academy/fancy-captcha-ui. A cross-package contract:
     * change it only additively. Never contains a secret.
     *
     * @return array{provider: string, siteKey: ?string, action: ?string, fields: array{honeypot: string, started: string, pow: string, token: string}, started: string, pow: array{enabled: bool, difficulty: int, challengeUrl: ?string}, consentCategory: ?string, configured: bool}
     */
    public function props(?string $action = null): array
    {
        $driver = $this->driverName();
        $isProvider = in_array($driver, self::PROVIDERS, true);
        $configured = ! $isProvider || $this->providerConfigured($driver);
        $consentCategory = $isProvider ? $this->consentCategory() : null;

        $provider = match (true) {
            ! $isProvider => 'builtin',
            ! $configured && ! $this->app->environment('production') => 'builtin',
            $driver === 'recaptcha' => 'recaptcha-'.($this->config("providers.recaptcha.version") === 'v3' ? 'v3' : 'v2'),
            default => $driver,
        };

        $router = $this->app->make('router');

        return [
            'provider' => $provider,
            'siteKey' => $isProvider && $configured ? (string) $this->config("providers.{$driver}.site_key") : null,
            'action' => $action ?? $this->config('action'),
            'fields' => $this->fields(),
            'started' => $this->app->make(FormTimestamp::class)->issue(),
            'pow' => [
                'enabled' => (bool) $this->config('pow.enabled', false)
                    || ($consentCategory !== null && (bool) $this->config('consent.fallback_pow', true)),
                'difficulty' => (int) $this->config('pow.difficulty', 18),
                'challengeUrl' => $router->has('fancy-captcha.challenge')
                    ? $this->app->make('url')->route('fancy-captcha.challenge', [], false)
                    : null,
            ],
            'consentCategory' => $consentCategory,
            'configured' => $configured,
        ];
    }

    /** @return array{honeypot: string, started: string, pow: string, token: string} */
    public function fields(): array
    {
        return Fields::resolve((array) $this->config('fields', []));
    }

    private function decide(Request $request, ?string $action): Verdict
    {
        $driver = $this->driverName();

        if (isset($this->custom[$driver])) {
            return ($this->custom[$driver])($this->app, (array) $this->config("providers.{$driver}", []))->verify($request, $action);
        }
        if ($driver === 'builtin') {
            return $this->builtin((bool) $this->config('pow.enabled', false))->verify($request, $action);
        }
        if (! in_array($driver, self::PROVIDERS, true)) {
            throw new InvalidCaptchaConfiguration("fancy-captcha.driver [{$driver}] is not a driver. Use builtin, turnstile, recaptcha, hcaptcha, or one registered with Captcha::extend().");
        }

        if (! $this->providerConfigured($driver)) {
            if ($this->app->environment('production')) {
                $this->logger()->error("fancy-captcha: {$driver} is selected but has no site key or secret. Every submission is refused until both are set.");

                return Verdict::fail($driver, 'provider_unconfigured');
            }
            $this->logger()->warning("fancy-captcha: {$driver} is selected but has no site key or secret, so this ".$this->app->environment().' environment is using the built-in checks only. Production would refuse every submission.');

            return $this->builtin((bool) $this->config('pow.enabled', false))->verify($request, $action);
        }

        $category = $this->consentCategory();
        if ($category !== null && ! $this->consentAllows($category, $request)) {
            return $this->builtin((bool) $this->config('consent.fallback_pow', true) || (bool) $this->config('pow.enabled', false))->verify($request, $action);
        }

        if ($this->config('builtin.with_providers', true)) {
            $first = $this->builtin(false)->verify($request, $action);
            if (! $first->passed) {
                return $first;
            }
        }

        return $this->provider($driver)->verify($request, $action);
    }

    private function builtin(bool $requirePow): BuiltinVerifier
    {
        return new BuiltinVerifier(
            $this->fields(),
            $this->app->make(FormTimestamp::class),
            $this->pow(),
            (int) $this->config('builtin.min_seconds', 3),
            (int) $this->config('builtin.max_seconds', 21600),
            $requirePow,
        );
    }

    private function provider(string $driver): SiteverifyVerifier
    {
        $class = match ($driver) {
            'turnstile' => TurnstileVerifier::class,
            'recaptcha' => RecaptchaVerifier::class,
            'hcaptcha' => HcaptchaVerifier::class,
        };
        $hostnames = $this->config('hostnames');

        return new $class(
            (array) $this->config("providers.{$driver}"),
            // Resolved per call, so Http::fake() in a host's test reaches it.
            $this->app->make(Http::class),
            $this->fields()['token'],
            is_array($hostnames) ? array_values(array_map('strval', $hostnames)) : null,
            (float) $this->config('timeout', 3.0),
            (float) $this->config('connect_timeout', 2.0),
            $this->config('action'),
        );
    }

    private function pow(): ProofOfWork
    {
        return $this->app->make(ProofOfWork::class);
    }

    private function driverName(): string
    {
        return (string) $this->config('driver', 'builtin');
    }

    private function providerConfigured(string $driver): bool
    {
        return (string) $this->config("providers.{$driver}.site_key") !== ''
            && (string) $this->config("providers.{$driver}.secret_key") !== '';
    }

    private function consentCategory(): ?string
    {
        $category = $this->config('consent.category');

        return is_string($category) && $category !== '' ? $category : null;
    }

    /**
     * fancy-compliance is a SOFT dependency: its contract is only asked when
     * it exists and is bound. Absent either, a gated provider counts as not
     * consented to, and the built-in fallback runs.
     */
    private function consentAllows(string $category, Request $request): bool
    {
        $contract = 'FancyCompliance\\Contracts\\ConsentGate';
        if (! interface_exists($contract) || ! $this->app->bound($contract)) {
            return false;
        }

        return $this->app->make($contract)->allows($category, $request) === true;
    }

    private function logRefusal(Request $request, ?string $action, Verdict $verdict): void
    {
        $context = [
            'driver' => $verdict->driver,
            'reason' => $verdict->reason,
            'action' => $action,
            'route' => $request->route()?->getName() ?? $request->path(),
            ...$verdict->details,
        ];
        if ($this->config('log.ip', false)) {
            $context['ip'] = $request->ip();
        }
        $this->logger()->info('fancy-captcha refused a submission.', $context);
    }

    private function logger(): LoggerInterface
    {
        $channel = $this->config('log.channel');
        $log = $this->app->make('log');

        return $channel === null ? $log : $log->channel((string) $channel);
    }

    private function config(string $key, mixed $default = null): mixed
    {
        return $this->app->make('config')->get('fancy-captcha.'.$key, $default);
    }
}
