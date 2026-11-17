<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\DataTransfer\LoginResult;
use WebServCo\Auth\Model\RememberLogin;

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
     * The setup step: the application's page shows the new method to the pending account (a QR code from
     * webservco/mfa) and passes the confirming response here. The method is enabled and the login completes.
     */
    public function completeSecondFactorSetup(string $methodId, string $response): LoginResult;

    /**
     * Ids of the methods the pending login can use: the enabled ones, or all of them for a setup. [] when nothing is
     * pending.
     *
     * @return list<string>
     */
    public function getSecondFactorMethods(): array;

    /**
     * The password step. LoggedIn when no second factor applies; SecondFactorRequired and SecondFactorSetupRequired
     * leave a pending login for 5 minutes. RememberLogin::Yes keeps the login after the browser closes, set once
     * the login completes (after the second factor, if any).
     */
    public function login(
        string $login,
        string $password,
        RememberLogin $rememberLogin = RememberLogin::No,
    ): LoginResult;

    /**
     * Starts the challenge of a method for the pending login and returns what the page needs ('' for an
     * authenticator app). Null when nothing is pending or the method isn't available.
     */
    public function startSecondFactor(string $methodId): ?string;
}
