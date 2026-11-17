<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\DataTransfer\LoginResult;

/**
 * The login sequence: password, then a second factor if the account has one (or must set one up), then logged in.
 */
interface LoginServiceInterface
{
    /**
     * After a second factor was accepted, the login completes with a new session id.
     */
    public function completeSecondFactor(string $methodId, string $response): LoginResult;

    /**
     * After the application's setup page: completes the login once the method is enabled for the pending account.
     */
    public function completeSecondFactorSetup(string $methodId): LoginResult;

    /**
     * Ids of the methods the pending login can use: the enabled ones, or all of them for a setup. [] when nothing is
     * pending.
     *
     * @return list<string>
     */
    public function getSecondFactorMethods(): array;

    /**
     * The password step. LoggedIn when no second factor applies; SecondFactorRequired and SecondFactorSetupRequired
     * leave a pending login for 5 minutes.
     */
    public function login(string $login, string $password): LoginResult;

    /**
     * Starts the challenge of a method for the pending login and returns what the page needs ('' for an
     * authenticator app). Null when nothing is pending or the method isn't available.
     */
    public function startSecondFactor(string $methodId): ?string;
}
