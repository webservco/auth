<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\DataTransfer\AuthenticationAttempt;

interface CredentialVerificationServiceInterface
{
    /**
     * Checks a login and password, with throttling and the upgrade of old hashes. It doesn't touch the session.
     */
    public function verifyCredentials(string $login, string $password): AuthenticationAttempt;
}
