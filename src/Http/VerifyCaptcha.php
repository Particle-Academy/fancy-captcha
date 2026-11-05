<?php

declare(strict_types=1);

namespace FancyCaptcha\Http;

use Closure;
use FancyCaptcha\CaptchaManager;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware `captcha` / `captcha:<action>`. Verifies a form's POST
 * before the controller sees it, so a refused bot never creates a user, sends
 * a mail or stores a message. GET, HEAD and OPTIONS pass untouched, so the
 * same middleware can sit on a route that renders the form.
 *
 * A refusal is a ValidationException under `fancy-captcha.error_key`, which
 * Laravel turns into a redirect back with errors, an Inertia error bag, or a
 * 422 JSON response, whichever the request expects.
 */
final class VerifyCaptcha
{
    public function __construct(private readonly CaptchaManager $captcha) {}

    public function handle(Request $request, Closure $next, ?string $action = null): Response
    {
        if (! $request->isMethodSafe() && ! $this->captcha->verify($request, $action)->passed) {
            throw ValidationException::withMessages([
                (string) config('fancy-captcha.error_key', 'captcha') => $this->captcha->failureMessage(),
            ]);
        }

        return $next($request);
    }
}
