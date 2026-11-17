<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Override;
use WebServCo\Auth\Contract\LegacyPasswordVerifierInterface;

use function hash_equals;
use function md5;

/**
 * Unsalted MD5, as in old tables. Counts its calls, so a test can see that it is used only once.
 */
final class Md5LegacyPasswordVerifier implements LegacyPasswordVerifierInterface
{
    private int $calls = 0;

    public function getCalls(): int
    {
        return $this->calls;
    }

    #[Override]
    public function verify(string $password, string $legacyHash): bool
    {
        $this->calls += 1;

        return hash_equals($legacyHash, md5($password));
    }
}
