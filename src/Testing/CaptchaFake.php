<?php

declare(strict_types=1);

namespace FancyCaptcha\Testing;

use FancyCaptcha\Contracts\Verifier;
use FancyCaptcha\Verdict;
use Illuminate\Http\Request;
use PHPUnit\Framework\Assert;

/**
 * `Captcha::fake()` in a host's tests: every verification passes (or, with
 * `fails()`, fails) without a real check, and is recorded for assertions.
 * The manager refuses to create one in production.
 */
final class CaptchaFake implements Verifier
{
    /** @var list<?string> the action of every verification, in order */
    private array $verified = [];

    public function __construct(private bool $passes = true) {}

    public function passes(): self
    {
        $this->passes = true;

        return $this;
    }

    public function fails(): self
    {
        $this->passes = false;

        return $this;
    }

    public function verify(Request $request, ?string $action = null): Verdict
    {
        $this->verified[] = $action;

        return $this->passes ? Verdict::pass('fake') : Verdict::fail('fake', 'faked_failure');
    }

    /** At least one verification happened, for this action when one is given. */
    public function assertVerified(?string $action = null): void
    {
        $matching = $action === null ? $this->verified : array_filter($this->verified, fn (?string $a): bool => $a === $action);
        $seen = implode(', ', array_map(fn (?string $a): string => $a ?? 'none', $this->verified));
        Assert::assertNotEmpty($matching, $action === null
            ? 'Expected a captcha verification; none happened.'
            : "Expected a captcha verification for action [{$action}]; saw [{$seen}].");
    }

    public function assertNotVerified(): void
    {
        Assert::assertSame([], $this->verified, 'Expected no captcha verification; '.count($this->verified).' happened.');
    }

    public function assertVerifiedCount(int $count): void
    {
        Assert::assertCount($count, $this->verified, "Expected {$count} captcha verifications; ".count($this->verified).' happened.');
    }
}
