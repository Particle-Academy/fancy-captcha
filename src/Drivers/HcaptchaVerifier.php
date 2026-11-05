<?php

declare(strict_types=1);

namespace FancyCaptcha\Drivers;

use FancyCaptcha\Verdict;

/**
 * hCaptcha. Sends the site key, which hCaptcha recommends so a token solved
 * for another site is refused. Enterprise accounts also return a risk score,
 * where HIGHER is worse; it is checked only when a threshold is configured.
 */
final class HcaptchaVerifier extends SiteverifyVerifier
{
    public function name(): string
    {
        return 'hcaptcha';
    }

    protected function nativeField(): string
    {
        return 'h-captcha-response';
    }

    protected function extraPayload(): array
    {
        return ['sitekey' => (string) $this->config['site_key']];
    }

    protected function inspect(array $answer, ?string $action): ?Verdict
    {
        $threshold = $this->config['score_threshold'] ?? null;
        if ($threshold === null) {
            return null;
        }
        $score = $answer['score'] ?? null;
        if (! is_int($score) && ! is_float($score) || $score > (float) $threshold) {
            return $this->fail('score_above_threshold');
        }

        return null;
    }
}
