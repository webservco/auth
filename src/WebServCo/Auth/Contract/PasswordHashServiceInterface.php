<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

interface PasswordHashServiceInterface
{
    /**
     * `password_hash()` with PHP's default algorithm: use it for new accounts and password changes.
     */
    public function hash(string $password): string;

    /**
     * False for hashes `password_hash()` didn't produce, for example the unsalted MD5 of legacy tables.
     */
    public function isPasswordHash(string $hash): bool;

    public function needsRehash(string $hash): bool;

    /**
     * Takes as long as a verification, and is always false: for logins without a usable hash, so the response time
     * doesn't reveal them. It follows the hashing settings, as PHP's default cost changes (12 since PHP 8.4).
     */
    public function simulateVerification(string $password): bool;

    public function verify(string $password, string $hash): bool;
}
