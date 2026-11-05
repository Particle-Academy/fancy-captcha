<?php

declare(strict_types=1);

namespace FancyCompliance\Contracts;

use Illuminate\Http\Request;

/**
 * The exact signature of particle-academy/fancy-compliance's ConsentGate
 * (fancy-compliance 0.1.0, src/Contracts/ConsentGate.php), which is NOT a
 * dependency of this package. Autoload-dev only.
 *
 * What this does NOT prove: that a host's real ConsentManager answers the way
 * the tests' bindings do. It proves fancy-captcha asks the right question and
 * acts on the answer.
 */
interface ConsentGate
{
    public function allows(string $category, ?Request $request = null): bool;
}
