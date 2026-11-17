<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\InMemorySessionService;
use WebServCo\Auth\Service\CsrfTokenService;

#[CoversClass(CsrfTokenService::class)]
final class CsrfTokenServiceTest extends TestCase
{
    public function testTheTokenIsRandomAndStableForTheSession(): void
    {
        $service = new CsrfTokenService(new InMemorySessionService());
        $token = $service->getToken();

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $token);
        self::assertSame($token, $service->getToken());
    }

    public function testOnlyTheSessionsTokenIsValid(): void
    {
        $service = new CsrfTokenService(new InMemorySessionService());
        $token = $service->getToken();

        self::assertTrue($service->isValidToken($token));
        self::assertFalse($service->isValidToken($token . '0'));
        self::assertFalse($service->isValidToken(''));
    }

    public function testWithoutATokenNothingIsValidAndNoTokenIsCreated(): void
    {
        $sessionService = new InMemorySessionService();
        $service = new CsrfTokenService($sessionService);

        self::assertFalse($service->isValidToken('anything'));
        self::assertSame([], $sessionService->getSessionData());
    }

    public function testANewSessionGetsANewToken(): void
    {
        $sessionService = new InMemorySessionService();
        $service = new CsrfTokenService($sessionService);
        $oldToken = $service->getToken();
        $sessionService->destroy();

        self::assertFalse($service->isValidToken($oldToken));
        self::assertNotSame($oldToken, $service->getToken());
    }

    public function testAnUnexpectedStoredValueCountsAsNoToken(): void
    {
        $sessionService = new InMemorySessionService();
        $sessionService->setSessionDataItem('auth.csrf', ['not', 'a', 'token']);
        $service = new CsrfTokenService($sessionService);

        self::assertFalse($service->isValidToken('not'));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $service->getToken());
    }
}
