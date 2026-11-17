<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract\Storage;

use WebServCo\Auth\Model\DataTransfer\RememberToken;

/**
 * Remember-me tokens of one realm.
 */
interface RememberTokenStorageInterface
{
    /**
     * Deletes the token; false when it was already gone.
     */
    public function delete(string $selector): bool;

    /**
     * Removes the account's expired tokens.
     */
    public function deleteExpired(string $accountId, int $now): bool;

    public function fetch(string $selector): ?RememberToken;

    public function save(RememberToken $rememberToken, int $createdAt): bool;
}
