<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\AuthFixture;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\CsrfTokenService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;

/**
 * The logged-in state. The pending state is in AuthenticationServicePendingTest.
 */
#[CoversClass(AuthenticationService::class)]
#[UsesClass(Account::class)]
#[UsesClass(AccountState::class)]
#[UsesClass(AccountTableConfiguration::class)]
#[UsesClass(CsrfTokenService::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDOAccountStorage::class)]
#[UsesClass(RealmConfiguration::class)]
final class AuthenticationServiceTest extends TestCase
{
    public function testLoginGivesANewSessionIdAndTheAccount(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();

        self::assertNull($service->getAuthenticatedAccount());

        $service->login(AuthFixture::ACCOUNT_ID);

        self::assertSame(1, $fixture->getSessionService()->getRegenerations());
        self::assertEquals(new Account('42', 'editor', ['role' => 'editor']), $service->getAuthenticatedAccount());
    }

    public function testTheLoginEndsAfterThirtyIdleMinutes(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->login(AuthFixture::ACCOUNT_ID);
        $fixture->advanceClock(1799);

        self::assertNotNull($service->getAuthenticatedAccount());

        $fixture->advanceClock(1800);

        self::assertNull($service->getAuthenticatedAccount());
    }

    public function testActivityKeepsTheLoginUpToTwelveHours(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->login(AuthFixture::ACCOUNT_ID);
        $stillLoggedIn = [];

        for ($request = 1; $request <= 26; $request += 1) {
            $fixture->advanceClock(1700);
            $stillLoggedIn[] = $service->getAuthenticatedAccount() !== null;
        }

        // 25 × 1700 s is under 12 hours (43 200 s); the 26th request, at 44 200 s, is over.
        self::assertSame(25, $this->countTrue($stillLoggedIn));
        self::assertFalse($stillLoggedIn[25] ?? true);
    }

    public function testLogoutEverywhereEndsTheLoginButNotTheNextOne(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->login(AuthFixture::ACCOUNT_ID);
        $service->logoutEverywhere(AuthFixture::ACCOUNT_ID);

        self::assertNull($service->getAuthenticatedAccount());

        $service->login(AuthFixture::ACCOUNT_ID);

        self::assertNotNull($service->getAuthenticatedAccount());
    }

    public function testADeactivatedAccountLosesAccessAtOnce(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->login(AuthFixture::ACCOUNT_ID);
        $fixture->deactivateAccount();

        self::assertNull($service->getAuthenticatedAccount());
    }

    public function testLogoutDestroysTheSession(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->login(AuthFixture::ACCOUNT_ID);
        $service->logout();

        self::assertTrue($fixture->getSessionService()->isDestroyed());
        self::assertNull($service->getAuthenticatedAccount());
    }

    public function testRealmsDoNotShareALogin(): void
    {
        $fixture = new AuthFixture();
        $fixture->createAuthenticationService('admin')->login(AuthFixture::ACCOUNT_ID);

        self::assertNull($fixture->createAuthenticationService('customer')->getAuthenticatedAccount());
        self::assertNotNull($fixture->createAuthenticationService('admin')->getAuthenticatedAccount());
    }

    public function testTheLoginGetsANewCsrfToken(): void
    {
        $fixture = new AuthFixture();
        $csrfTokenService = new CsrfTokenService($fixture->getSessionService());
        $token = $csrfTokenService->getToken();
        $fixture->createAuthenticationService()->login(AuthFixture::ACCOUNT_ID);

        self::assertFalse($csrfTokenService->isValidToken($token));
        self::assertNotSame($token, $csrfTokenService->getToken());
    }

    /**
     * @param list<bool> $values
     */
    private function countTrue(array $values): int
    {
        $count = 0;

        foreach ($values as $value) {
            if (!$value) {
                continue;
            }

            $count += 1;
        }

        return $count;
    }
}
