<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract\Storage;

use WebServCo\Auth\Model\DataTransfer\AccountState;

/**
 * Login state per account in one realm: failures, lock, epoch, last login.
 */
interface AccountStateStorageInterface
{
    /**
     * A zero state when the account has no row yet.
     */
    public function fetch(string $accountId): AccountState;

    /**
     * Adds one to the epoch and returns the new value: every session of the account ends.
     */
    public function incrementEpoch(string $accountId): int;

    public function lock(string $accountId, int $lockedUntil): bool;

    /**
     * Adds one failure and returns the new count.
     */
    public function recordFailure(string $accountId): int;

    /**
     * Clears the failures and the lock, and records the login time.
     */
    public function recordSuccess(string $accountId, int $loginAt): bool;
}
