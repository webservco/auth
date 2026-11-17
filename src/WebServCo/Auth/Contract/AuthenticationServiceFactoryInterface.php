<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;

interface AuthenticationServiceFactoryInterface
{
    /**
     * A remember-me configuration turns remember-me on for the realm; not for admin realms.
     */
    public function createAuthenticationService(
        RealmConfiguration $realmConfiguration,
        AccountTableConfiguration $accountTableConfiguration,
        ?RememberMeConfiguration $rememberMeConfiguration = null,
    ): AuthenticationServiceInterface;
}
