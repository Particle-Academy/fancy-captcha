<?php

declare(strict_types=1);

namespace FancyCaptcha\Http;

use FancyCaptcha\CaptchaManager;
use Illuminate\Http\JsonResponse;

/**
 * `GET {prefix}/challenge`: one fresh proof-of-work challenge. A GET because
 * it needs no CSRF token and changes nothing a visitor owns; it is throttled
 * per IP and never cached, because every response must be a new challenge.
 */
final class ChallengeController
{
    public function __invoke(CaptchaManager $captcha): JsonResponse
    {
        return new JsonResponse($captcha->issueChallenge(), 200, [
            'Cache-Control' => 'no-store, private',
        ]);
    }
}
