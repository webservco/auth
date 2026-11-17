<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use Override;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use WebServCo\Auth\Contract\CredentialVerificationServiceInterface;
use WebServCo\Auth\Contract\LegacyPasswordVerifierInterface;
use WebServCo\Auth\Contract\PasswordHashServiceInterface;
use WebServCo\Auth\Contract\Storage\AccountStateStorageInterface;
use WebServCo\Auth\Contract\Storage\AccountStorageInterface;
use WebServCo\Auth\Model\AuthenticationAttemptResult;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AuthenticationAttempt;

use function max;

/**
 * Throttling: from the 5th consecutive failure the account waits 1 minute, doubling up to 15 minutes. A success
 * resets the count. There is no permanent lock, which would let anyone lock a user out.
 *
 * Every path costs one bcrypt operation, so the response time doesn't tell unknown, throttled or legacy accounts apart.
 *
 * phpcs: "Signature of method should be placed on a single line" conflicts with "Expected 0 blank lines between
 * attribute and its target, both are on same line": a #[SensitiveParameter] parameter needs a multi-line signature.
 *
 * @phpcs:disable SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature.RequiredSingleLineSignature
 */
final readonly class CredentialVerificationService implements CredentialVerificationServiceInterface
{
    private const int THROTTLE_FAILURES = 5;
    private const int THROTTLE_FIRST_SECONDS = 60;
    private const int THROTTLE_MAX_SECONDS = 900;

    public function __construct(
        private AccountStorageInterface $accountStorage,
        private AccountStateStorageInterface $accountStateStorage,
        private ClockInterface $clock,
        private PasswordHashServiceInterface $passwordHashService,
        private ?LegacyPasswordVerifierInterface $legacyPasswordVerifier = null,
    ) {
    }

    #[Override]
    public function verifyCredentials(
        string $login,
        #[SensitiveParameter]
        string $password,
    ): AuthenticationAttempt {
        $credential = $this->accountStorage->fetchCredential($login);

        if ($credential === null) {
            $this->passwordHashService->simulateVerification($password);

            return new AuthenticationAttempt(AuthenticationAttemptResult::InvalidCredentials, null, 0);
        }

        $now = $this->clock->now()->getTimestamp();
        $state = $this->accountStateStorage->fetch($credential->accountId);
        // Counted before the slow password check: a success clears the count again.
        $isCounted = $this->accountStateStorage->countAttempt(
            $credential->accountId,
            $now,
            self::THROTTLE_FAILURES,
            $now + $this->getWait($state->failedAttempts + 1),
        );

        if (!$isCounted) {
            $this->passwordHashService->simulateVerification($password);
            $lockedUntil = $this->accountStateStorage->fetch($credential->accountId)->lockedUntil ?? $now;

            return new AuthenticationAttempt(AuthenticationAttemptResult::Throttled, null, max(1, $lockedUntil - $now));
        }

        if (!$this->checkPassword($credential, $password)) {
            return new AuthenticationAttempt(AuthenticationAttemptResult::InvalidCredentials, null, 0);
        }

        $this->accountStateStorage->recordSuccess($credential->accountId, $now);

        return new AuthenticationAttempt(AuthenticationAttemptResult::Success, $credential->accountId, 0);
    }

    private function checkLegacyPassword(
        AccountCredential $credential,
        #[SensitiveParameter]
        string $password,
    ): bool {
        $this->passwordHashService->simulateVerification($password);

        if ($this->legacyPasswordVerifier === null) {
            return false;
        }

        if (!$this->legacyPasswordVerifier->verify($password, $credential->passwordHash)) {
            return false;
        }

        $this->accountStorage->updatePasswordHash($credential->accountId, $this->passwordHashService->hash($password));

        return true;
    }

    private function checkPassword(
        AccountCredential $credential,
        #[SensitiveParameter]
        string $password,
    ): bool {
        if (!$this->passwordHashService->isPasswordHash($credential->passwordHash)) {
            return $this->checkLegacyPassword($credential, $password);
        }

        if (!$this->passwordHashService->verify($password, $credential->passwordHash)) {
            return false;
        }

        if ($this->passwordHashService->needsRehash($credential->passwordHash)) {
            $this->accountStorage->updatePasswordHash(
                $credential->accountId,
                $this->passwordHashService->hash($password),
            );
        }

        return true;
    }

    /**
     * 60 s at the 5th failure in a row, then 120, 240, 480, then 900 from the 9th on. Below the 5th the storage sets
     * no lock.
     */
    private function getWait(int $failedAttempts): int
    {
        $doublings = max(0, $failedAttempts - self::THROTTLE_FAILURES);

        if ($doublings >= 4) {
            return self::THROTTLE_MAX_SECONDS;
        }

        return self::THROTTLE_FIRST_SECONDS << $doublings;
    }
}
