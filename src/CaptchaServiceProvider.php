<?php

declare(strict_types=1);

namespace FancyCaptcha;

use FancyCaptcha\Http\ChallengeController;
use FancyCaptcha\Http\VerifyCaptcha;
use FancyCaptcha\Support\FormTimestamp;
use FancyCaptcha\Support\ProofOfWork;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Cache\RateLimiter;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\ServiceProvider;

final class CaptchaServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // A DEEP merge, not mergeConfigFrom(): that merges top-level keys only,
        // so a host config setting just `providers.turnstile.site_key` would
        // silently drop the endpoint and every other default beside it.
        if (! ($this->app instanceof \Illuminate\Contracts\Foundation\CachesConfiguration && $this->app->configurationIsCached())) {
            $config = $this->app->make('config');
            $config->set('fancy-captcha', array_replace_recursive(
                require __DIR__.'/../config/fancy-captcha.php',
                (array) $config->get('fancy-captcha', []),
            ));
        }
        $this->app->singleton(CaptchaManager::class, fn ($app) => new CaptchaManager($app));
        $this->app->bind(FormTimestamp::class, fn ($app) => new FormTimestamp($app->make('encrypter')));
        $this->app->bind(ProofOfWork::class, function ($app) {
            $config = $app->make('config');
            $store = $config->get('fancy-captcha.pow.store');

            return new ProofOfWork(
                $app->make('cache')->store($store === null ? null : (string) $store),
                (int) $config->get('fancy-captcha.pow.difficulty', 18),
                (int) $config->get('fancy-captcha.pow.ttl', 300),
            );
        });
    }

    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'fancy-captcha');
        $this->publishes([__DIR__.'/../config/fancy-captcha.php' => $this->app->configPath('fancy-captcha.php')], 'fancy-captcha-config');
        $this->publishes([__DIR__.'/../lang' => $this->app->langPath('vendor/fancy-captcha')], 'fancy-captcha-lang');

        $config = $this->app->make('config');
        $router = $this->app->make('router');
        $router->aliasMiddleware('captcha', VerifyCaptcha::class);

        if ($config->get('fancy-captcha.routes.enabled', true)) {
            $perMinute = max(1, (int) $config->get('fancy-captcha.routes.per_minute', 30));
            $this->app->make(RateLimiter::class)->for(
                'fancy-captcha',
                fn ($request) => Limit::perMinute($perMinute)->by('fancy-captcha|'.$request->ip()),
            );

            $router->group([
                'prefix' => (string) $config->get('fancy-captcha.routes.prefix', 'fancy-captcha'),
                'middleware' => [ThrottleRequests::class.':fancy-captcha', ...(array) $config->get('fancy-captcha.routes.middleware', [])],
            ], function ($router): void {
                $router->get('challenge', ChallengeController::class)->name('fancy-captcha.challenge');
            });
            // The name was attached after the route was added; make it findable now.
            $router->getRoutes()->refreshNameLookups();
        }

        // Inertia is optional: share only when the host has it. A closure, so
        // every page gets a FRESH signed timestamp.
        if ($config->get('fancy-captcha.inertia.share', true) && class_exists(\Inertia\Inertia::class)) {
            \Inertia\Inertia::share(
                (string) $config->get('fancy-captcha.inertia.key', 'fancyCaptcha'),
                fn (): array => $this->app->make(CaptchaManager::class)->props(),
            );
        }
    }
}
