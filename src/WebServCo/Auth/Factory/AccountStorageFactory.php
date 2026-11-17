<?php

declare(strict_types=1);

namespace WebServCo\Auth\Factory;

use Override;
use WebServCo\Auth\Contract\AccountStorageFactoryInterface;
use WebServCo\Auth\Contract\Storage\AccountStateStorageInterface;
use WebServCo\Auth\Contract\Storage\AccountStorageInterface;
use WebServCo\Auth\Contract\Storage\RememberTokenStorageInterface;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Auth\Service\Storage\PDORememberTokenStorage;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;

/**
 * The tables are `auth_account_state` and `auth_remember_token` (`resources/auth.sql`); for other names, build the
 * PDO storages yourself.
 */
final readonly class AccountStorageFactory implements AccountStorageFactoryInterface
{
    public function __construct(
        private DataExtractionContainerInterface $dataExtractionContainer,
        private PDOContainerInterface $pdoContainer,
    ) {
    }

    #[Override]
    public function createAccountStateStorage(string $realm): AccountStateStorageInterface
    {
        return new PDOAccountStateStorage($this->dataExtractionContainer, $this->pdoContainer, $realm);
    }

    #[Override]
    public function createAccountStorage(AccountTableConfiguration $accountTableConfiguration): AccountStorageInterface
    {
        return new PDOAccountStorage($accountTableConfiguration, $this->dataExtractionContainer, $this->pdoContainer);
    }

    #[Override]
    public function createRememberTokenStorage(string $realm): RememberTokenStorageInterface
    {
        return new PDORememberTokenStorage($this->dataExtractionContainer, $this->pdoContainer, $realm);
    }
}
