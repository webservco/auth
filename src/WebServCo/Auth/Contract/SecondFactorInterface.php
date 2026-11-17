<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

use WebServCo\Auth\Model\SecondFactorResult;

/**
 * One second-factor method, implemented by the application: today an authenticator app (an adapter around
 * webservco/mfa), later possibly an email code or a passkey. LoginService calls it with the pending account's id and
 * the attempt id, so a challenge can be bound to this login attempt only. Each method throttles its own failures.
 */
interface SecondFactorInterface
{
    /**
     * The setup step: checks the response that confirms the account's new method (the first code from an
     * authenticator app) and enables the method. It runs within the pending login, so a setup finished in another
     * session never completes this one. Keep what the setup returns for the page (webservco/mfa's recovery codes).
     */
    public function confirmSetup(string $accountId, string $attemptId, string $response): SecondFactorResult;

    /**
     * A stable id, unique among the methods given to LoginService: "totp", "email", "passkey"...
     */
    public function getId(): string;

    /**
     * Whether the account has this method set up.
     */
    public function isEnabled(string $accountId): bool;

    /**
     * Prepares the challenge and returns what the page needs: '' for an authenticator app, the WebAuthn request
     * options (JSON) for a passkey. An email code would be sent here.
     */
    public function startChallenge(string $accountId, string $attemptId): string;

    /**
     * Checks the answer: a typed code, or a passkey assertion (JSON).
     */
    public function verify(string $accountId, string $attemptId, string $response): SecondFactorResult;
}
