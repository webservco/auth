<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract\Storage;

use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;

/**
 * The application's account table, read through its mapping. Inactive accounts are never returned.
 */
interface AccountStorageInterface
{
    public function fetchAccount(string $accountId): ?Account;

    public function fetchCredential(string $login): ?AccountCredential;

    public function updatePasswordHash(string $accountId, string $passwordHash): bool;
}
