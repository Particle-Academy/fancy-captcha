<?php

declare(strict_types=1);

namespace FancyCaptcha\Drivers;

use FancyCaptcha\Verdict;

/**
 * Google reCAPTCHA. v2 (checkbox) is a plain success; v3 (invisible) is a
 * score from 0.0 (bot) to 1.0 (person) plus the action the page executed.
 * For v3 the score must be a number at or above the threshold, and when an
 * action is expected it must be reported and match: Google's own guidance is
 * to verify the action, and a v3 token for "login" must not pass "signup".
 */
final class RecaptchaVerifier extends SiteverifyVerifier
{
    public function name(): string
    {
        return 'recaptcha';
    }

    protected function nativeField(): string
    {
        return 'g-recaptcha-response';
    }

    protected function inspect(array $answer, ?string $action): ?Verdict
    {
        if (($this->config['version'] ?? 'v2') !== 'v3') {
            return null;
        }
        $score = $answer['score'] ?? null;
        $threshold = (float) ($this->config['score_threshold'] ?? 0.5);
        if (! is_int($score) && ! is_float($score) || $score < $threshold) {
            return $this->fail('score_below_threshold', is_int($score) || is_float($score) ? ['score' => (float) $score] : []);
        }
        if ($action !== null && ($answer['action'] ?? null) !== $action) {
            return $this->fail('action_mismatch');
        }

        return null;
    }
}
