<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

/**
 * "Remember me": a long-lived cookie that logs the account in again after the browser closes. Used through
 * AuthenticationService; not meant for admin realms.
 */
interface RememberMeServiceInterface
{
    /**
     * Deletes the current token and expires the cookie.
     */
    public function forget(): bool;

    /**
     * Issues a new token for the account and sets the cookie.
     */
    public function remember(string $accountId): bool;

    /**
     * The account of a valid remember-me cookie, or null; an invalid cookie is removed with its token.
     */
    public function restore(): ?string;
}
