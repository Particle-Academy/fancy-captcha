<?php

declare(strict_types=1);

namespace FancyCaptcha\Drivers;

use FancyCaptcha\Contracts\Verifier;
use FancyCaptcha\Support\FormTimestamp;
use FancyCaptcha\Support\ProofOfWork;
use FancyCaptcha\Verdict;
use Illuminate\Http\Request;

/**
 * The built-in checks, cheapest first: honeypot, signed timing, and
 * (when on) a single-use proof-of-work. No third party, no network.
 */
final class BuiltinVerifier implements Verifier
{
    /** @param array{honeypot: string, started: string, pow: string, token: string} $fields */
    public function __construct(
        private readonly array $fields,
        private readonly FormTimestamp $timestamp,
        private readonly ProofOfWork $pow,
        private readonly int $minSeconds,
        private readonly int $maxSeconds,
        private readonly bool $requirePow,
    ) {}

    public function verify(Request $request, ?string $action = null): Verdict
    {
        $honeypot = $request->input($this->fields['honeypot']);
        if ($honeypot !== null && $honeypot !== '') {
            return Verdict::fail('builtin', 'honeypot_filled');
        }

        $started = $request->input($this->fields['started']);
        if (! is_string($started) || $started === '') {
            return Verdict::fail('builtin', 'timestamp_missing');
        }
        $age = $this->timestamp->age($started);
        if ($age === null) {
            return Verdict::fail('builtin', 'timestamp_invalid');
        }
        if ($age < $this->minSeconds) {
            return Verdict::fail('builtin', 'too_fast', ['age' => $age, 'min' => $this->minSeconds]);
        }
        if ($age > $this->maxSeconds) {
            return Verdict::fail('builtin', 'timestamp_expired', ['age' => $age, 'max' => $this->maxSeconds]);
        }

        if ($this->requirePow) {
            $reason = $this->pow->redeem($request->input($this->fields['pow']));
            if ($reason !== null) {
                return Verdict::fail('builtin', $reason);
            }
        }

        return Verdict::pass('builtin');
    }
}
