<?php

declare(strict_types=1);

namespace FancyCaptcha;

use InvalidArgumentException;

/** The host's fancy-captcha config cannot be used as written. Thrown, never logged-and-ignored. */
final class InvalidCaptchaConfiguration extends InvalidArgumentException {}
