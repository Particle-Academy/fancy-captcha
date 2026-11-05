<?php

declare(strict_types=1);

namespace FancyCaptcha\Support;

use FancyCaptcha\InvalidCaptchaConfiguration;
use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * Proof-of-work: the server issues a random challenge, the browser searches
 * for a nonce such that SHA-256("<id>:<nonce>") starts with `difficulty`
 * zero bits, and the server checks it with ONE hash.
 *
 * It raises the cost of mass submission; it does not stop a determined
 * attacker with native code. That is the honest claim, and the reason it sits
 * beside the honeypot and timing rather than replacing a provider.
 *
 * Single use is the invariant. A challenge is accepted at most once:
 *
 *  1. The challenge entry must still exist (issued by us, not expired).
 *  2. A "spent" marker is ADDED atomically. If another request already added
 *     it, this one loses: that is what stops two concurrent submissions
 *     redeeming one solution on a store where get-then-forget would race.
 *  3. The challenge entry is forgotten.
 *  4. Only then is the hash checked, so a wrong answer still burns the
 *     challenge and cannot be retried against it.
 *
 * Strict single use under concurrency needs a store whose add() is atomic
 * (array, redis, memcached, database, dynamodb). The file store's is not.
 */
final class ProofOfWork
{
    public const ALGORITHM = 'sha256-leading-zero-bits';

    private const ID_LENGTH = 22;

    private const MAX_NONCE_DIGITS = 16;

    private const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    public function __construct(
        private readonly Cache $cache,
        private readonly int $difficulty,
        private readonly int $ttl,
    ) {}

    /** @return array{id: string, difficulty: int, expiresIn: int, algorithm: string} */
    public function issue(): array
    {
        $difficulty = $this->difficulty();
        $id = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $this->cache->put($this->key($id), $difficulty, $this->ttl);

        return ['id' => $id, 'difficulty' => $difficulty, 'expiresIn' => $this->ttl, 'algorithm' => self::ALGORITHM];
    }

    /** Null when the solution is accepted; otherwise the reason, for the log. */
    public function redeem(mixed $solution): ?string
    {
        if ($solution === null || $solution === '') {
            return 'pow_missing';
        }
        if (! is_string($solution) || strlen($solution) > self::ID_LENGTH + 1 + self::MAX_NONCE_DIGITS) {
            return 'pow_invalid';
        }
        $id = substr($solution, 0, self::ID_LENGTH);
        $nonce = substr($solution, self::ID_LENGTH + 1);
        if (strlen($solution) < self::ID_LENGTH + 2
            || $solution[self::ID_LENGTH] !== ':'
            || strspn($id, self::B64URL) !== self::ID_LENGTH
            || strspn($nonce, '0123456789') !== strlen($nonce)) {
            return 'pow_invalid';
        }

        $difficulty = $this->cache->get($this->key($id));
        if (! is_int($difficulty)) {
            return 'pow_unknown';
        }
        if (! $this->cache->add('fancy-captcha:pow-spent:'.$id, true, $this->ttl)) {
            return 'pow_replayed';
        }
        $this->cache->forget($this->key($id));

        return self::leadingZeroBits(hash('sha256', $id.':'.$nonce, true)) >= $difficulty ? null : 'pow_insufficient';
    }

    public static function leadingZeroBits(string $binary): int
    {
        $bits = 0;
        $length = strlen($binary);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($binary[$i]);
            if ($byte === 0) {
                $bits += 8;

                continue;
            }
            for ($mask = 0x80; ($byte & $mask) === 0; $mask >>= 1) {
                $bits++;
            }

            break;
        }

        return $bits;
    }

    private function difficulty(): int
    {
        if ($this->difficulty < 8 || $this->difficulty > 32) {
            throw new InvalidCaptchaConfiguration('fancy-captcha.pow.difficulty must be between 8 and 32 bits.');
        }

        return $this->difficulty;
    }

    private function key(string $id): string
    {
        return 'fancy-captcha:pow:'.$id;
    }
}
