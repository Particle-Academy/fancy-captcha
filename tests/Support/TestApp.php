<?php

declare(strict_types=1);

namespace FancyCaptcha\Tests\Support;

use FancyCaptcha\CaptchaServiceProvider;
use Illuminate\Cache\CacheServiceProvider;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Encryption\EncryptionServiceProvider;
use Illuminate\Filesystem\FilesystemServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Translation\TranslationServiceProvider;
use Illuminate\Support\Facades\Facade;
use Illuminate\Validation\ValidationServiceProvider;

/**
 * A hand-built Laravel 13 kernel: the framework this package integrates with,
 * booted directly, with no orchestra/testbench (the estate's approach, as in
 * fancy-compliance and change-council).
 *
 * The array cache store, so every proof-of-work challenge lives and dies with
 * the test. No database. The HTTP client is the real one; every test that can
 * reach a provider fakes it and forbids stray requests, so nothing here can
 * call Cloudflare, Google or hCaptcha.
 */
final class TestApp
{
    public const APP_KEY = 'base64:a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=';

    /** @param array<string, mixed> $config dotted keys merged over the defaults */
    public static function boot(array $config = [], string $env = 'testing'): Application
    {
        $base = sys_get_temp_dir().DIRECTORY_SEPARATOR.'fancy-captcha-tests';
        foreach (['/config', '/lang'] as $dir) {
            if (! is_dir($base.$dir)) {
                mkdir($base.$dir, 0777, true);
            }
        }
        $app = new Application($base);
        $app->useConfigPath($base.'/config');
        $app->useLangPath($base.'/lang');
        $app['env'] = $env;
        Container::setInstance($app);
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);

        $repository = new Repository([
            'app' => ['key' => self::APP_KEY, 'cipher' => 'AES-256-CBC', 'env' => $env, 'debug' => false, 'locale' => 'en', 'fallback_locale' => 'en', 'url' => 'https://forms.example.test'],
            'cache' => ['default' => 'array', 'stores' => ['array' => ['driver' => 'array', 'serialize' => false]], 'prefix' => 'test'],
            'logging' => ['default' => 'null', 'channels' => ['null' => ['driver' => 'monolog', 'handler' => \Monolog\Handler\NullHandler::class]]],
        ]);
        foreach ($config as $key => $value) {
            $repository->set($key, $value);
        }
        $app->instance('config', $repository);

        foreach ([FilesystemServiceProvider::class, EncryptionServiceProvider::class, CacheServiceProvider::class,
            TranslationServiceProvider::class, ValidationServiceProvider::class] as $provider) {
            $app->register($provider);
        }
        $app->register(CaptchaServiceProvider::class);
        $app->boot();

        return $app;
    }
}
