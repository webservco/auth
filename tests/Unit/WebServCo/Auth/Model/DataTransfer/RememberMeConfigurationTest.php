<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Model\DataTransfer;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Session\Model\DataTransfer\CookieConfiguration;

#[CoversClass(RememberMeConfiguration::class)]
final class RememberMeConfigurationTest extends TestCase
{
    public function testAHostOnlyCookieIsAccepted(): void
    {
        $cookie = $this->createCookie(30, '', true, 'Lax');

        self::assertSame('__Host-remember', (new RememberMeConfiguration('__Host-remember', $cookie))->cookieName);
    }

    public function testAnInvalidNameIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Invalid cookie name.');

        $cookie = $this->createCookie(30, '', true, 'Lax');

        self::assertSame('', (new RememberMeConfiguration("remember\n", $cookie))->cookieName);
    }

    public function testAHostOnlyCookieWithADomainIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A "__Host-" cookie needs the path "/" and no domain.');

        $cookie = $this->createCookie(30, 'example.com', true, 'Lax');

        self::assertSame('', (new RememberMeConfiguration('__Host-remember', $cookie))->cookieName);
    }

    public function testALifetimeBelowOneSecondIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The remember-me lifetime must be at least 1 second.');

        $cookie = $this->createCookie(0, '', true, 'Lax');

        self::assertSame('', (new RememberMeConfiguration('remember', $cookie))->cookieName);
    }

    public function testACookieWithoutSecureIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The remember-me cookie must be HttpOnly and Secure.');

        $cookie = $this->createCookie(30, '', false, 'Lax');

        self::assertSame('', (new RememberMeConfiguration('remember', $cookie))->cookieName);
    }

    public function testSameSiteNoneIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The remember-me cookie must be SameSite Lax or Strict.');

        $cookie = $this->createCookie(30, '', true, 'None');

        self::assertSame('', (new RememberMeConfiguration('remember', $cookie))->cookieName);
    }

    /**
     * @param 'Lax'|'None'|'Strict' $sameSite
     */
    private function createCookie(int $lifetime, string $domain, bool $secure, string $sameSite): CookieConfiguration
    {
        return new CookieConfiguration($lifetime, '/', $domain, $secure, true, $sameSite);
    }
}
