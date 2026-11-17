<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

/**
 * Implemented by an application whose account table still holds old hashes, for example unsalted MD5.
 * When it accepts a password, the old hash is replaced with a `password_hash()` hash, so it is used once per account.
 */
interface LegacyPasswordVerifierInterface
{
    public function verify(string $password, string $legacyHash): bool;
}
