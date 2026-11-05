<?php

declare(strict_types=1);

namespace FancyCaptcha\Contracts;

use FancyCaptcha\Verdict;
use Illuminate\Http\Request;

/**
 * One way of deciding whether a submission came from a person. Drivers are
 * built per verification, so they may hold request-scoped state.
 *
 * A verifier must FAIL CLOSED: anything it cannot positively confirm is a
 * refusal. It must never put a token, a solution or a timestamp into the
 * Verdict's details, because details are logged.
 */
interface Verifier
{
    public function verify(Request $request, ?string $action = null): Verdict;
}
