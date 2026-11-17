<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use InvalidArgumentException;
use Override;
use SensitiveParameter;
use WebServCo\Auth\Contract\AuthenticationServiceInterface;
use WebServCo\Auth\Contract\CredentialVerificationServiceInterface;
use WebServCo\Auth\Contract\LoginServiceInterface;
use WebServCo\Auth\Contract\SecondFactorInterface;
use WebServCo\Auth\Model\AuthenticationAttemptResult;
use WebServCo\Auth\Model\DataTransfer\LoginResult;
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Auth\Model\PendingStep;
use WebServCo\Auth\Model\SecondFactorPolicy;
use WebServCo\Auth\Model\SecondFactorResult;

use function in_array;
use function preg_match;

/**
 * The second factor is always called with the pending login's own account id and attempt id, so an answer for one
 * account can never complete the login of another.
 *
 * phpcs: "Signature of method should be placed on a single line" conflicts with "Expected 0 blank lines between
 * attribute and its target, both are on same line": a #[SensitiveParameter] parameter needs a multi-line signature.
 *
 * @phpcs:disable SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature.RequiredSingleLineSignature
 */
final readonly class LoginService implements LoginServiceInterface
{
    /**
     * @param list<\WebServCo\Auth\Contract\SecondFactorInterface> $secondFactors
     */
    public function __construct(
        private AuthenticationServiceInterface $authenticationService,
        private CredentialVerificationServiceInterface $credentialVerificationService,
        private SecondFactorPolicy $secondFactorPolicy,
        private array $secondFactors = [],
    ) {
        if ($secondFactorPolicy === SecondFactorPolicy::Required && $secondFactors === []) {
            throw new InvalidArgumentException('A required second factor needs at least one method.');
        }

        $this->assertMethodIds();
    }

    #[Override]
    public function completeSecondFactor(
        string $methodId,
        #[SensitiveParameter]
        string $response,
    ): LoginResult {
        $pendingAuthentication = $this->authenticationService->getPendingAuthentication();

        if ($pendingAuthentication === null || $pendingAuthentication->step !== PendingStep::SecondFactor) {
            return new LoginResult(LoginStatus::NoPendingLogin);
        }

        $secondFactor = $this->findEnabledMethod($pendingAuthentication->accountId, $methodId);

        if ($secondFactor === null) {
            return new LoginResult(LoginStatus::MethodNotAvailable);
        }

        $result = $secondFactor->verify(
            $pendingAuthentication->accountId,
            $pendingAuthentication->attemptId,
            $response,
        );

        return match ($result) {
            SecondFactorResult::Accepted => $this->completeLogin(),
            SecondFactorResult::Locked => new LoginResult(LoginStatus::SecondFactorLocked),
            SecondFactorResult::Rejected => new LoginResult(LoginStatus::SecondFactorRejected),
        };
    }

    #[Override]
    public function completeSecondFactorSetup(string $methodId): LoginResult
    {
        $pendingAuthentication = $this->authenticationService->getPendingAuthentication();

        if ($pendingAuthentication === null || $pendingAuthentication->step !== PendingStep::SecondFactorSetup) {
            return new LoginResult(LoginStatus::NoPendingLogin);
        }

        // The application's setup page enabled the method; check that it really is enabled for this account.
        if ($this->findEnabledMethod($pendingAuthentication->accountId, $methodId) === null) {
            return new LoginResult(LoginStatus::MethodNotAvailable);
        }

        return $this->completeLogin();
    }

    #[Override]
    public function getSecondFactorMethods(): array
    {
        $pendingAuthentication = $this->authenticationService->getPendingAuthentication();
        $methodIds = [];

        if ($pendingAuthentication === null) {
            return $methodIds;
        }

        foreach ($this->secondFactors as $secondFactor) {
            if (
                $pendingAuthentication->step === PendingStep::SecondFactor
                && !$secondFactor->isEnabled($pendingAuthentication->accountId)
            ) {
                continue;
            }

            $methodIds[] = $secondFactor->getId();
        }

        return $methodIds;
    }

    #[Override]
    public function login(
        string $login,
        #[SensitiveParameter]
        string $password,
    ): LoginResult {
        $attempt = $this->credentialVerificationService->verifyCredentials($login, $password);

        if ($attempt->result === AuthenticationAttemptResult::Throttled) {
            return new LoginResult(LoginStatus::Throttled, $attempt->retryAfterSeconds);
        }

        if ($attempt->accountId === null) {
            return new LoginResult(LoginStatus::InvalidCredentials);
        }

        if ($this->hasEnabledMethod($attempt->accountId)) {
            $this->authenticationService->startPendingAuthentication($attempt->accountId, PendingStep::SecondFactor);

            return new LoginResult(LoginStatus::SecondFactorRequired);
        }

        if ($this->secondFactorPolicy === SecondFactorPolicy::Required) {
            $this->authenticationService->startPendingAuthentication(
                $attempt->accountId,
                PendingStep::SecondFactorSetup,
            );

            return new LoginResult(LoginStatus::SecondFactorSetupRequired);
        }

        $this->authenticationService->login($attempt->accountId);

        return new LoginResult(LoginStatus::LoggedIn);
    }

    #[Override]
    public function startSecondFactor(string $methodId): ?string
    {
        $pendingAuthentication = $this->authenticationService->getPendingAuthentication();

        if ($pendingAuthentication === null || $pendingAuthentication->step !== PendingStep::SecondFactor) {
            return null;
        }

        return $this->findEnabledMethod($pendingAuthentication->accountId, $methodId)
            ?->startChallenge($pendingAuthentication->accountId, $pendingAuthentication->attemptId);
    }

    private function assertMethodIds(): bool
    {
        $methodIds = [];

        foreach ($this->secondFactors as $secondFactor) {
            $methodId = $secondFactor->getId();

            if (preg_match('/^[A-Za-z0-9_-]{1,32}$/', $methodId) !== 1 || in_array($methodId, $methodIds, true)) {
                throw new InvalidArgumentException(
                    'Second factor ids must be unique: 1 to 32 letters, digits, "_" or "-".',
                );
            }

            $methodIds[] = $methodId;
        }

        return true;
    }

    private function completeLogin(): LoginResult
    {
        if (!$this->authenticationService->completePendingAuthentication()) {
            return new LoginResult(LoginStatus::NoPendingLogin);
        }

        return new LoginResult(LoginStatus::LoggedIn);
    }

    private function findEnabledMethod(string $accountId, string $methodId): ?SecondFactorInterface
    {
        foreach ($this->secondFactors as $secondFactor) {
            if ($secondFactor->getId() !== $methodId || !$secondFactor->isEnabled($accountId)) {
                continue;
            }

            return $secondFactor;
        }

        return null;
    }

    private function hasEnabledMethod(string $accountId): bool
    {
        foreach ($this->secondFactors as $secondFactor) {
            if ($secondFactor->isEnabled($accountId)) {
                return true;
            }
        }

        return false;
    }
}
