<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use Override;
use Psr\Clock\ClockInterface;
use WebServCo\Auth\Contract\AuthenticationServiceInterface;
use WebServCo\Auth\Contract\RememberMeServiceInterface;
use WebServCo\Auth\Contract\Storage\AccountStateStorageInterface;
use WebServCo\Auth\Contract\Storage\AccountStorageInterface;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\PendingAuthentication;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\PendingStep;
use WebServCo\Auth\Model\RememberLogin;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Session\Contract\SessionServiceInterface;

use function bin2hex;
use function is_array;
use function random_bytes;

/**
 * Session keys: `auth.<realm>` for the login, `auth.<realm>.pending` for a pending one. Each state change gets a
 * new session id, so an id known before (session fixation) is worth nothing after.
 */
final readonly class AuthenticationService implements AuthenticationServiceInterface
{
    public function __construct(
        private AccountStorageInterface $accountStorage,
        private AccountStateStorageInterface $accountStateStorage,
        private ClockInterface $clock,
        private DataExtractionContainerInterface $dataExtractionContainer,
        private RealmConfiguration $realmConfiguration,
        private SessionServiceInterface $sessionService,
        private ?RememberMeServiceInterface $rememberMeService = null,
    ) {
    }

    #[Override]
    public function getAuthenticatedAccount(): ?Account
    {
        $entry = $this->readEntry($this->getLoginKey());

        if ($entry === null) {
            return $this->restoreRememberedLogin();
        }

        $now = $this->getTime();
        $account = $this->fetchValidAccount($entry, $now);

        if ($account === null) {
            $this->sessionService->unsetSessionDataItem($this->getLoginKey());

            return $this->restoreRememberedLogin();
        }

        $entry['lastActivityAt'] = $now;
        $this->sessionService->setSessionDataItem($this->getLoginKey(), $entry);

        return $account;
    }

    #[Override]
    public function getPendingAuthentication(): ?PendingAuthentication
    {
        $entry = $this->readEntry($this->getPendingKey());

        if ($entry === null) {
            return null;
        }

        $extraction = $this->dataExtractionContainer->getStrictArrayDataExtractionService();
        $startedAt = $extraction->getInt($entry, 'startedAt');
        $step = $this->getStep($extraction->getString($entry, 'step'));

        if ($step === null || $startedAt + $this->realmConfiguration->pendingTimeout <= $this->getTime()) {
            $this->sessionService->unsetSessionDataItem($this->getPendingKey());

            return null;
        }

        return new PendingAuthentication(
            $extraction->getString($entry, 'accountId'),
            $extraction->getString($entry, 'attemptId'),
            $step,
            $startedAt,
            $this->getRememberLogin($extraction->getString($entry, 'rememberLogin', RememberLogin::No->name)),
        );
    }

    #[Override]
    public function login(string $accountId, RememberLogin $rememberLogin = RememberLogin::No): bool
    {
        $now = $this->getTime();
        $this->sessionService->regenerateId();
        $this->sessionService->unsetSessionDataItem($this->getPendingKey());
        $this->sessionService->setSessionDataItem(
            $this->getLoginKey(),
            [
                'accountId' => $accountId,
                'authenticatedAt' => $now,
                'epoch' => $this->accountStateStorage->fetch($accountId)->epoch,
                'lastActivityAt' => $now,
            ],
        );

        if ($rememberLogin === RememberLogin::Yes) {
            $this->rememberMeService?->remember($accountId);
        }

        return true;
    }

    #[Override]
    public function logout(): bool
    {
        $this->rememberMeService?->forget();

        return $this->sessionService->destroy();
    }

    #[Override]
    public function logoutEverywhere(string $accountId): bool
    {
        $this->accountStateStorage->incrementEpoch($accountId);

        return true;
    }

    #[Override]
    public function startPendingAuthentication(
        string $accountId,
        PendingStep $step,
        RememberLogin $rememberLogin = RememberLogin::No,
    ): PendingAuthentication {
        $pendingAuthentication = new PendingAuthentication(
            $accountId,
            bin2hex(random_bytes(16)),
            $step,
            $this->getTime(),
            $rememberLogin,
        );
        $this->sessionService->regenerateId();
        $this->sessionService->unsetSessionDataItem($this->getLoginKey());
        $this->sessionService->setSessionDataItem(
            $this->getPendingKey(),
            [
                'accountId' => $pendingAuthentication->accountId,
                'attemptId' => $pendingAuthentication->attemptId,
                'rememberLogin' => $rememberLogin->name,
                'startedAt' => $pendingAuthentication->startedAt,
                'step' => $step->name,
            ],
        );

        return $pendingAuthentication;
    }

    /**
     * The account, if the session is within its timeouts and epoch and the account is still active.
     *
     * Session data is mixed (SessionServiceInterface::getSessionData()); each value is read with a strict type.
     *
     * @phpcs:disable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint.DisallowedMixedTypeHint
     * @param array<mixed> $entry
     */
    private function fetchValidAccount(array $entry, int $now): ?Account
    {
        $extraction = $this->dataExtractionContainer->getStrictArrayDataExtractionService();
        $accountId = $extraction->getString($entry, 'accountId');

        if (
            $extraction->getInt($entry, 'lastActivityAt') + $this->realmConfiguration->idleTimeout <= $now
            || $extraction->getInt($entry, 'authenticatedAt') + $this->realmConfiguration->absoluteTimeout <= $now
            || $extraction->getInt($entry, 'epoch') !== $this->accountStateStorage->fetch($accountId)->epoch
        ) {
            return null;
        }

        return $this->accountStorage->fetchAccount($accountId);
    }
    // @phpcs:enable

    private function getLoginKey(): string
    {
        return 'auth.' . $this->realmConfiguration->name;
    }

    private function getPendingKey(): string
    {
        return $this->getLoginKey() . '.pending';
    }

    private function getRememberLogin(string $name): RememberLogin
    {
        return match ($name) {
            RememberLogin::Yes->name => RememberLogin::Yes,
            default => RememberLogin::No,
        };
    }

    private function getStep(string $name): ?PendingStep
    {
        return match ($name) {
            PendingStep::SecondFactor->name => PendingStep::SecondFactor,
            PendingStep::SecondFactorSetup->name => PendingStep::SecondFactorSetup,
            default => null,
        };
    }

    private function getTime(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    /**
     * A remember-me cookie, when the realm has remember-me: a new session login for its account. It is the realm's
     * login after a session timeout too; an epoch change or a disabled account ends both.
     */
    private function restoreRememberedLogin(): ?Account
    {
        $rememberMeService = $this->rememberMeService;

        if ($rememberMeService === null) {
            return null;
        }

        $accountId = $rememberMeService->restore();

        if ($accountId === null) {
            return null;
        }

        $account = $this->accountStorage->fetchAccount($accountId);

        // Deactivated since the token was issued.
        if ($account === null) {
            $rememberMeService->forget();

            return null;
        }

        $this->login($accountId);

        return $account;
    }

    /**
     * Session data is mixed (SessionServiceInterface::getSessionData()); the caller reads each value strictly.
     *
     * @phpcs:disable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint.DisallowedMixedTypeHint
     * @return ?array<mixed>
     */
    private function readEntry(string $key): ?array
    {
        $sessionData = $this->sessionService->getSessionData();

        if (!isset($sessionData[$key]) || !is_array($sessionData[$key])) {
            return null;
        }

        return $sessionData[$key];
    }
}
