<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Model\SecondFactorPolicy;

interface LoginServiceFactoryInterface
{
    /**
     * Pass the realm's remember-me configuration here too (the same as for createAuthenticationService()), or
     * RememberLogin::Yes is ignored.
     *
     * @param list<\WebServCo\Auth\Contract\SecondFactorInterface> $secondFactors
     */
    public function createLoginService(
        RealmConfiguration $realmConfiguration,
        AccountTableConfiguration $accountTableConfiguration,
        SecondFactorPolicy $secondFactorPolicy = SecondFactorPolicy::Optional,
        array $secondFactors = [],
        ?LegacyPasswordVerifierInterface $legacyPasswordVerifier = null,
        ?RememberMeConfiguration $rememberMeConfiguration = null,
    ): LoginServiceInterface;
}
