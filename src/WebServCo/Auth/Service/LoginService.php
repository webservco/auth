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
use WebServCo\Auth\Model\RememberLogin;
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

        return $this->completeOn(
            $result,
            $pendingAuthentication->accountId,
            $pendingAuthentication->rememberLogin,
            $pendingAuthentication->epoch,
        );
    }

    /**
     * The proof comes in this call: a method enabled elsewhere (another session finishing its own setup) is not
     * enough.
     */
    #[Override]
    public function completeSecondFactorSetup(
        string $methodId,
        #[SensitiveParameter]
        string $response,
    ): LoginResult {
        $pendingAuthentication = $this->authenticationService->getPendingAuthentication();

        if ($pendingAuthentication === null || $pendingAuthentication->step !== PendingStep::SecondFactorSetup) {
            return new LoginResult(LoginStatus::NoPendingLogin);
        }

        $secondFactor = $this->findMethod($methodId);

        if ($secondFactor === null) {
            return new LoginResult(LoginStatus::MethodNotAvailable);
        }

        $result = $secondFactor->confirmSetup(
            $pendingAuthentication->accountId,
            $pendingAuthentication->attemptId,
            $response,
        );

        return $this->completeOn(
            $result,
            $pendingAuthentication->accountId,
            $pendingAuthentication->rememberLogin,
            $pendingAuthentication->epoch,
        );
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
        RememberLogin $rememberLogin = RememberLogin::No,
    ): LoginResult {
        $attempt = $this->credentialVerificationService->verifyCredentials($login, $password);

        if ($attempt->result === AuthenticationAttemptResult::Throttled) {
            return new LoginResult(LoginStatus::Throttled, $attempt->retryAfterSeconds);
        }

        if ($attempt->accountId === null) {
            return new LoginResult(LoginStatus::InvalidCredentials);
        }

        $step = $this->getPendingStep($attempt->accountId);

        if ($step !== null) {
            return $this->startPendingStep($attempt->accountId, $attempt->epoch, $step, $rememberLogin);
        }

        if (!$this->authenticationService->login($attempt->accountId, $rememberLogin, $attempt->epoch)) {
            return new LoginResult(LoginStatus::InvalidCredentials);
        }

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

            if (preg_match('/^[A-Za-z0-9_-]{1,32}\z/', $methodId) !== 1 || in_array($methodId, $methodIds, true)) {
                throw new InvalidArgumentException(
                    'Second factor ids must be unique: 1 to 32 letters, digits, "_" or "-".',
                );
            }

            $methodIds[] = $methodId;
        }

        return true;
    }

    private function completeLogin(string $accountId, RememberLogin $rememberLogin, int $epoch): LoginResult
    {
        if (!$this->authenticationService->login($accountId, $rememberLogin, $epoch)) {
            return new LoginResult(LoginStatus::NoPendingLogin);
        }

        return new LoginResult(LoginStatus::LoggedIn);
    }

    /**
     * The pending login's account, remember-me request and epoch complete the login when the method accepted.
     */
    private function completeOn(
        SecondFactorResult $result,
        string $accountId,
        RememberLogin $rememberLogin,
        int $epoch,
    ): LoginResult {
        return match ($result) {
            SecondFactorResult::Accepted => $this->completeLogin($accountId, $rememberLogin, $epoch),
            SecondFactorResult::Locked => new LoginResult(LoginStatus::SecondFactorLocked),
            SecondFactorResult::Rejected => new LoginResult(LoginStatus::SecondFactorRejected),
        };
    }

    private function findEnabledMethod(string $accountId, string $methodId): ?SecondFactorInterface
    {
        $secondFactor = $this->findMethod($methodId);

        if ($secondFactor === null || !$secondFactor->isEnabled($accountId)) {
            return null;
        }

        return $secondFactor;
    }

    private function findMethod(string $methodId): ?SecondFactorInterface
    {
        foreach ($this->secondFactors as $secondFactor) {
            if ($secondFactor->getId() === $methodId) {
                return $secondFactor;
            }
        }

        return null;
    }

    /**
     * After the password: a challenge for an enabled method, a setup where the policy requires a method, or nothing.
     */
    private function getPendingStep(string $accountId): ?PendingStep
    {
        if ($this->hasEnabledMethod($accountId)) {
            return PendingStep::SecondFactor;
        }

        if ($this->secondFactorPolicy === SecondFactorPolicy::Required) {
            return PendingStep::SecondFactorSetup;
        }

        return null;
    }

    private function startPendingStep(
        string $accountId,
        int $epoch,
        PendingStep $step,
        RememberLogin $rememberLogin,
    ): LoginResult {
        $this->authenticationService->startPendingAuthentication($accountId, $step, $rememberLogin, $epoch);

        return new LoginResult(
            match ($step) {
                PendingStep::SecondFactor => LoginStatus::SecondFactorRequired,
                PendingStep::SecondFactorSetup => LoginStatus::SecondFactorSetupRequired,
            },
        );
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
