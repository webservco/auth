<?php

declare(strict_types=1);

namespace WebServCo\Auth\Factory;

use Override;
use WebServCo\Auth\Contract\AccountStorageFactoryInterface;
use WebServCo\Auth\Contract\AuthenticationServiceFactoryInterface;
use WebServCo\Auth\Contract\LegacyPasswordVerifierInterface;
use WebServCo\Auth\Contract\LoginServiceFactoryInterface;
use WebServCo\Auth\Contract\LoginServiceInterface;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Model\SecondFactorPolicy;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\LoginService;
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\SystemClock;

final readonly class LoginServiceFactory implements LoginServiceFactoryInterface
{
    public function __construct(
        private AccountStorageFactoryInterface $accountStorageFactory,
        private AuthenticationServiceFactoryInterface $authenticationServiceFactory,
    ) {
    }

    #[Override]
    public function createLoginService(
        RealmConfiguration $realmConfiguration,
        AccountTableConfiguration $accountTableConfiguration,
        SecondFactorPolicy $secondFactorPolicy = SecondFactorPolicy::Optional,
        array $secondFactors = [],
        ?LegacyPasswordVerifierInterface $legacyPasswordVerifier = null,
        ?RememberMeConfiguration $rememberMeConfiguration = null,
    ): LoginServiceInterface {
        return new LoginService(
            $this->authenticationServiceFactory->createAuthenticationService(
                $realmConfiguration,
                $accountTableConfiguration,
                $rememberMeConfiguration,
            ),
            new CredentialVerificationService(
                $this->accountStorageFactory->createAccountStorage($accountTableConfiguration),
                $this->accountStorageFactory->createAccountStateStorage($realmConfiguration->name),
                new SystemClock(),
                new PasswordHashService(),
                $legacyPasswordVerifier,
            ),
            $secondFactorPolicy,
            $secondFactors,
        );
    }
}
