<?php

declare(strict_types=1);

namespace WebServCo\Auth\Factory;

use Override;
use WebServCo\Auth\Contract\AccountStorageFactoryInterface;
use WebServCo\Auth\Contract\AuthenticationServiceFactoryInterface;
use WebServCo\Auth\Contract\AuthenticationServiceInterface;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\RememberMeService;
use WebServCo\Auth\Service\SystemClock;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Session\Contract\SessionServiceInterface;
use WebServCo\Session\Service\CookieService;

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
        ?RememberMeConfiguration $rememberMeConfiguration = null,
    ): AuthenticationServiceInterface {
        $accountStateStorage = $this->accountStorageFactory->createAccountStateStorage($realmConfiguration->name);
        $clock = new SystemClock();

        return new AuthenticationService(
            $this->accountStorageFactory->createAccountStorage($accountTableConfiguration),
            $accountStateStorage,
            $clock,
            $this->dataExtractionContainer,
            $realmConfiguration,
            $this->sessionService,
            $rememberMeConfiguration === null
                ? null
                : new RememberMeService(
                    $accountStateStorage,
                    $clock,
                    new CookieService(),
                    $rememberMeConfiguration,
                    $this->accountStorageFactory->createRememberTokenStorage($realmConfiguration->name),
                ),
        );
    }
}
