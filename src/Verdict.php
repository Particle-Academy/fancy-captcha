<?php

declare(strict_types=1);

namespace FancyCaptcha;

/**
 * The answer for one submission. `reason` and `details` are for the LOG: the
 * visitor only ever sees the generic message. Neither ever carries a token, a
 * solution or a timestamp, only codes and numbers.
 */
final readonly class Verdict
{
    /** @param array<string, int|float|string|bool|list<string>> $details */
    private function __construct(
        public bool $passed,
        public string $driver,
        public ?string $reason,
        public array $details,
    ) {}

    public static function pass(string $driver): self
    {
        return new self(true, $driver, null, []);
    }

    /** @param array<string, int|float|string|bool|list<string>> $details */
    public static function fail(string $driver, string $reason, array $details = []): self
    {
        return new self(false, $driver, $reason, $details);
    }
}
