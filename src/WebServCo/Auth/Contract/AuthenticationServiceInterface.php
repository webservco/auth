<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\PendingAuthentication;
use WebServCo\Auth\Model\PendingStep;
use WebServCo\Auth\Model\RememberLogin;

/**
 * The login state of one realm, kept in the session. The application starts the session first.
 */
interface AuthenticationServiceInterface
{
    /**
     * The logged-in account, or null: not logged in, idle or absolute timeout, logged out everywhere, or the account
     * is no longer active. Call it on every request; it also refreshes the idle time. A pending login is never
     * returned here. Without a valid session login, a remember-me cookie (when the realm has remember-me) logs in
     * again.
     */
    public function getAuthenticatedAccount(): ?Account;

    /**
     * The pending login, or null when there is none or it expired.
     */
    public function getPendingAuthentication(): ?PendingAuthentication;

    /**
     * Logs the account in with a new session id, ending any pending login. RememberLogin::Yes also sets the
     * remember-me cookie, when the realm has remember-me. $epoch is the account's epoch when its password was
     * checked: after a "log out everywhere" since, nothing is logged in and the result is false.
     */
    public function login(
        string $accountId,
        RememberLogin $rememberLogin = RememberLogin::No,
        ?int $epoch = null,
    ): bool;

    /**
     * Destroys the session, on the server and in the browser, and forgets the remember-me token.
     */
    public function logout(): bool;

    /**
     * Every session of the account ends on its next request: use it on password change, MFA reset, account disable.
     */
    public function logoutEverywhere(string $accountId): bool;

    /**
     * The password was right, a step remains. New session id; nothing is logged in until completion. $epoch: as for
     * login(), kept until the completion (the current one when null).
     */
    public function startPendingAuthentication(
        string $accountId,
        PendingStep $step,
        RememberLogin $rememberLogin = RememberLogin::No,
        ?int $epoch = null,
    ): PendingAuthentication;
}
