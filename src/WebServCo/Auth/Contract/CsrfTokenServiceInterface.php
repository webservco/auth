<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

/**
 * A CSRF token for the forms of this session: put it in every form that changes something, the login form included,
 * and check it before handling the submit.
 */
interface CsrfTokenServiceInterface
{
    /**
     * The session's token, created on first use.
     */
    public function getToken(): string;

    /**
     * Whether the submitted token is the session's token. Never creates a token.
     */
    public function isValidToken(string $token): bool;
}
