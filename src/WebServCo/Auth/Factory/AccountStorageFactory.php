<?php

declare(strict_types=1);

namespace WebServCo\Auth\Factory;

use Override;
use WebServCo\Auth\Contract\AccountStorageFactoryInterface;
use WebServCo\Auth\Contract\Storage\AccountStateStorageInterface;
use WebServCo\Auth\Contract\Storage\AccountStorageInterface;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;

/**
 * The state table is `auth_account_state` (`resources/auth.sql`); for another name, build PDOAccountStateStorage
 * yourself.
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
}
