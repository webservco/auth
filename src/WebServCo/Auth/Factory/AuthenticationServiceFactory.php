<?php

declare(strict_types=1);

namespace WebServCo\Auth\Factory;

use Override;
use WebServCo\Auth\Contract\AccountStorageFactoryInterface;
use WebServCo\Auth\Contract\AuthenticationServiceFactoryInterface;
use WebServCo\Auth\Contract\AuthenticationServiceInterface;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\SystemClock;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Session\Contract\SessionServiceInterface;

final readonly class AuthenticationServiceFactory implements AuthenticationServiceFactoryInterface
{
    public function __construct(
        private AccountStorageFactoryInterface $accountStorageFactory,
        private DataExtractionContainerInterface $dataExtractionContainer,
        private SessionServiceInterface $sessionService,
    ) {
    }

    #[Override]
    public function createAuthenticationService(
        RealmConfiguration $realmConfiguration,
        AccountTableConfiguration $accountTableConfiguration,
    ): AuthenticationServiceInterface {
        return new AuthenticationService(
            $this->accountStorageFactory->createAccountStorage($accountTableConfiguration),
            $this->accountStorageFactory->createAccountStateStorage($realmConfiguration->name),
            new SystemClock(),
            $this->dataExtractionContainer,
            $realmConfiguration,
            $this->sessionService,
        );
    }
}
