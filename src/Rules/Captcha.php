<?php

declare(strict_types=1);

namespace FancyCaptcha\Rules;

use Closure;
use FancyCaptcha\CaptchaManager;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * `'captcha' => [new Captcha('signup')]` in a form request. Implicit, so it
 * runs even when the attribute it is attached to is absent: a bot that drops
 * the field is not let through by omission.
 *
 * It verifies the CURRENT REQUEST, not the attribute's value. Used together
 * with the middleware, the manager's per-request memo means one check.
 */
final class Captcha implements ValidationRule
{
    public bool $implicit = true;

    public function __construct(private readonly ?string $action = null) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $manager = app(CaptchaManager::class);
        if (! $manager->verify(app('request'), $this->action)->passed) {
            $fail($manager->failureMessage());
        }
    }
}
