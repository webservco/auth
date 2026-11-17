<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\SecondFactorPolicy;

interface LoginServiceFactoryInterface
{
    /**
     * @param list<\WebServCo\Auth\Contract\SecondFactorInterface> $secondFactors
     */
    public function createLoginService(
        RealmConfiguration $realmConfiguration,
        AccountTableConfiguration $accountTableConfiguration,
        SecondFactorPolicy $secondFactorPolicy = SecondFactorPolicy::Optional,
        array $secondFactors = [],
        ?LegacyPasswordVerifierInterface $legacyPasswordVerifier = null,
    ): LoginServiceInterface;
}
