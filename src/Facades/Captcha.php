<?php

declare(strict_types=1);

namespace FancyCaptcha\Facades;

use FancyCaptcha\CaptchaManager;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \FancyCaptcha\Verdict verify(\Illuminate\Http\Request $request, ?string $action = null)
 * @method static bool passes(\Illuminate\Http\Request $request, ?string $action = null)
 * @method static array props(?string $action = null)
 * @method static array fields()
 * @method static array issueChallenge()
 * @method static string failureMessage()
 * @method static void extend(string $name, \Closure $factory)
 * @method static \FancyCaptcha\Testing\CaptchaFake fake(bool $passes = true)
 *
 * @see CaptchaManager
 */
final class Captcha extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return CaptchaManager::class;
    }
}
