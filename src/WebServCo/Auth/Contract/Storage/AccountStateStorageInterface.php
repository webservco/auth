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
     * Counts a login attempt before its password is checked, in one statement: false (nothing counted) while the
     * account is locked, so parallel requests can't pass a lock together. The attempt that reaches $lockFrom
     * attempts in a row locks the account until $lockedUntil; a success unlocks it. The count stops at 65535.
     */
    public function countAttempt(string $accountId, int $now, int $lockFrom, int $lockedUntil): bool;

    /**
     * A zero state when the account has no row yet.
     */
    public function fetch(string $accountId): AccountState;

    /**
     * Adds one to the epoch and returns the new value: every session of the account ends.
     */
    public function incrementEpoch(string $accountId): int;

    /**
     * Clears the attempts and the lock, and records the login time.
     */
    public function recordSuccess(string $accountId, int $loginAt): bool;
}
