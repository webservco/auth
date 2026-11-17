<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use Override;
use WebServCo\Auth\Contract\CsrfTokenServiceInterface;
use WebServCo\Session\Contract\SessionServiceInterface;

use function bin2hex;
use function hash_equals;
use function is_string;
use function random_bytes;

/**
 * Synchronizer token pattern (OWASP CSRF Prevention Cheat Sheet): one random token per session, compared in constant
 * time. It ends with the session, so logout() gives the next session a new one.
 */
final readonly class CsrfTokenService implements CsrfTokenServiceInterface
{
    private const string SESSION_KEY = 'auth.csrf';

    public function __construct(private SessionServiceInterface $sessionService,)
    {
    }

    #[Override]
    public function getToken(): string
    {
        $token = $this->readToken();

        if ($token !== null) {
            return $token;
        }

        $token = bin2hex(random_bytes(32));
        $this->sessionService->setSessionDataItem(self::SESSION_KEY, $token);

        return $token;
    }

    #[Override]
    public function isValidToken(string $token): bool
    {
        $sessionToken = $this->readToken();

        if ($sessionToken === null || $token === '') {
            return false;
        }

        return hash_equals($sessionToken, $token);
    }

    private function readToken(): ?string
    {
        $sessionData = $this->sessionService->getSessionData();

        if (!isset($sessionData[self::SESSION_KEY]) || !is_string($sessionData[self::SESSION_KEY])) {
            return null;
        }

        if ($sessionData[self::SESSION_KEY] === '') {
            return null;
        }

        return $sessionData[self::SESSION_KEY];
    }
}
