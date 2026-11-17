<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Contract\Storage\AccountStateStorageInterface;
use WebServCo\Auth\Contract\Storage\AccountStorageInterface;
use WebServCo\Auth\Contract\Storage\RememberTokenStorageInterface;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;

interface AccountStorageFactoryInterface
{
    public function createAccountStateStorage(string $realm): AccountStateStorageInterface;

    public function createAccountStorage(AccountTableConfiguration $accountTableConfiguration): AccountStorageInterface;

    public function createRememberTokenStorage(string $realm): RememberTokenStorageInterface;
}
