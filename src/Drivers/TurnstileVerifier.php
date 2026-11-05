<?php

declare(strict_types=1);

namespace FancyCaptcha\Drivers;

/** Cloudflare Turnstile. Reports `hostname`, and `action` when the widget set one. */
final class TurnstileVerifier extends SiteverifyVerifier
{
    public function name(): string
    {
        return 'turnstile';
    }

    protected function nativeField(): string
    {
        return 'cf-turnstile-response';
    }
}
