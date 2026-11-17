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
use function str_contains;

/**
 * Throttling: from the 5th consecutive failure the account waits 1 minute, doubling up to 15 minutes. A success
 * resets the count. There is no permanent lock, which would let anyone lock a user out.
 *
 * Every path costs one bcrypt operation, so the response time doesn't tell unknown, throttled or legacy accounts apart.
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
    public function verifyCredentials(string $login, #[SensitiveParameter] string $password,): AuthenticationAttempt
    {
        // bcrypt can't hash a NUL byte (password_hash() throws), and password_verify() ignores what follows one.
        if (str_contains($password, "\0")) {
            return new AuthenticationAttempt(AuthenticationAttemptResult::InvalidCredentials, null, 0);
        }

        $credential = $this->accountStorage->fetchCredential($login);

        if ($credential === null) {
            $this->passwordHashService->simulateVerification($password);

            return new AuthenticationAttempt(AuthenticationAttemptResult::InvalidCredentials, null, 0);
        }

        $now = $this->clock->now()->getTimestamp();
        $state = $this->accountStateStorage->fetch($credential->accountId);

        // Counted before the slow password check: a success clears the count again.
        if (!$this->countAttempt($credential->accountId, $state->failedAttempts, $now)) {
            return $this->refuseWhileLocked($credential->accountId, $password, $now);
        }

        if (!$this->checkPassword($credential, $password)) {
            return new AuthenticationAttempt(AuthenticationAttemptResult::InvalidCredentials, null, 0);
        }

        $this->accountStateStorage->recordSuccess($credential->accountId, $now);

        // The epoch from before the slow check: a "log out everywhere" during it must still end this login.
        return new AuthenticationAttempt(
            AuthenticationAttemptResult::Success,
            $credential->accountId,
            0,
            $state->epoch,
        );
    }

    private function checkLegacyPassword(
        #[SensitiveParameter]
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
        #[SensitiveParameter]
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

    private function countAttempt(string $accountId, int $failedAttempts, int $now): bool
    {
        return $this->accountStateStorage->countAttempt(
            $accountId,
            $now,
            self::THROTTLE_FAILURES,
            $now + $this->getWait($failedAttempts + 1),
        );
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

    private function refuseWhileLocked(
        string $accountId,
        #[SensitiveParameter]
        string $password,
        int $now,
    ): AuthenticationAttempt {
        $this->passwordHashService->simulateVerification($password);
        $lockedUntil = $this->accountStateStorage->fetch($accountId)->lockedUntil ?? $now;

        return new AuthenticationAttempt(AuthenticationAttemptResult::Throttled, null, max(1, $lockedUntil - $now));
    }
}
