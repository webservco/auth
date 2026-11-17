<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use InvalidArgumentException;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;
use WebServCo\Session\Model\DataTransfer\CookieConfiguration;

use function in_array;
use function preg_match;
use function str_starts_with;

/**
 * The remember-me cookie. Its lifetime is the token's lifetime, for example 30 days (2 592 000 s). It must be
 * HttpOnly and Secure, with SameSite Lax or Strict. A `__Host-` name (recommended) needs the path "/" and no domain.
 */
final readonly class RememberMeConfiguration implements DataTransferInterface
{
    public function __construct(public string $cookieName, public CookieConfiguration $cookieConfiguration,)
    {
        if (preg_match('/^(__Host-)?[A-Za-z0-9_-]{1,64}\z/', $cookieName) !== 1) {
            throw new InvalidArgumentException('Invalid cookie name.');
        }

        // Otherwise the browser refuses the cookie, without an error.
        if (
            str_starts_with($cookieName, '__Host-')
            && ($cookieConfiguration->path !== '/' || $cookieConfiguration->domain !== '')
        ) {
            throw new InvalidArgumentException('A "__Host-" cookie needs the path "/" and no domain.');
        }

        $this->assertSafeCookie($cookieConfiguration);
    }

    private function assertSafeCookie(CookieConfiguration $cookieConfiguration): bool
    {
        if ($cookieConfiguration->lifetime < 1) {
            throw new InvalidArgumentException('The remember-me lifetime must be at least 1 second.');
        }

        if (!$cookieConfiguration->httpOnly || !$cookieConfiguration->secure) {
            throw new InvalidArgumentException('The remember-me cookie must be HttpOnly and Secure.');
        }

        if (!in_array($cookieConfiguration->sameSite, ['Lax', 'Strict'], true)) {
            throw new InvalidArgumentException('The remember-me cookie must be SameSite Lax or Strict.');
        }

        return true;
    }
}
