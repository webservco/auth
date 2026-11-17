<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use Override;
use Psr\Clock\ClockInterface;
use UnexpectedValueException;
use WebServCo\Auth\Contract\RememberMeServiceInterface;
use WebServCo\Auth\Contract\Storage\AccountStateStorageInterface;
use WebServCo\Auth\Contract\Storage\RememberTokenStorageInterface;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberToken;
use WebServCo\Session\Contract\CookieServiceInterface;

use function bin2hex;
use function hash;
use function hash_equals;
use function preg_match;
use function random_bytes;
use function substr;

/**
 * Split tokens: the cookie holds "selector:validator" (random, hex), the database the selector and the validator's
 * SHA-256, so a copy of the table logs nobody in. A token lasts its lifetime from the login; logout deletes it, "log
 * out everywhere" ends all of them. It is not replaced on use: a browser restoring several tabs sends the same cookie
 * from all of them at once, and a single-use token would log all but one out.
 */
final readonly class RememberMeService implements RememberMeServiceInterface
{
    public function __construct(
        private AccountStateStorageInterface $accountStateStorage,
        private ClockInterface $clock,
        private CookieServiceInterface $cookieService,
        private RememberMeConfiguration $configuration,
        private RememberTokenStorageInterface $tokenStorage,
    ) {
    }

    #[Override]
    public function forget(): bool
    {
        $cookie = $this->readCookie();

        if ($cookie !== null) {
            $this->tokenStorage->delete($cookie['selector']);
        }

        return $this->cookieService->removeCookie(
            $this->configuration->cookieConfiguration,
            $this->configuration->cookieName,
        );
    }

    #[Override]
    public function remember(string $accountId): bool
    {
        $now = $this->clock->now()->getTimestamp();
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $this->tokenStorage->deleteExpired($accountId, $now);
        $this->tokenStorage->save(
            new RememberToken(
                $selector,
                $accountId,
                hash('sha256', $validator),
                $this->accountStateStorage->fetch($accountId)->epoch,
                $now + $this->configuration->cookieConfiguration->lifetime,
            ),
            $now,
        );

        return $this->cookieService->set(
            $this->configuration->cookieConfiguration,
            $this->configuration->cookieName,
            $selector . ':' . $validator,
        );
    }

    #[Override]
    public function restore(): ?string
    {
        $cookie = $this->readCookie();

        if ($cookie === null) {
            return null;
        }

        $token = $this->tokenStorage->fetch($cookie['selector']);

        if ($token === null || !$this->isUsable($token, $cookie['validator'])) {
            $this->forget();

            return null;
        }

        return $token->accountId;
    }

    private function isUsable(RememberToken $token, string $validator): bool
    {
        if (!hash_equals($token->validatorHash, hash('sha256', $validator))) {
            return false;
        }

        if ($token->expiresAt <= $this->clock->now()->getTimestamp()) {
            return false;
        }

        // "Log out everywhere" raised the epoch since this token was issued.
        return $token->epoch === $this->accountStateStorage->fetch($token->accountId)->epoch;
    }

    /**
     * @return ?array{selector:string,validator:string}
     */
    private function readCookie(): ?array
    {
        try {
            $value = $this->cookieService->getValue($this->configuration->cookieName);
        } catch (UnexpectedValueException) {
            // Not a string, for example "name[]=…": not a cookie this service set.
            return null;
        }

        if ($value === null || preg_match('/^[0-9a-f]{32}:[0-9a-f]{64}\z/', $value) !== 1) {
            return null;
        }

        return ['selector' => substr($value, 0, 32), 'validator' => substr($value, 33)];
    }
}
