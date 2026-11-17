<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\AuthFixture;
use Tests\Unit\Assets\RememberMeFixture;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberToken;
use WebServCo\Auth\Service\RememberMeService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDORememberTokenStorage;

use function hash;
use function str_repeat;
use function substr;

#[CoversClass(RememberMeService::class)]
#[UsesClass(AccountState::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDORememberTokenStorage::class)]
#[UsesClass(RememberMeConfiguration::class)]
#[UsesClass(RememberToken::class)]
final class RememberMeServiceTest extends TestCase
{
    public function testTheCookieHoldsASelectorAndAValidatorStoredOnlyAsAHash(): void
    {
        $fixture = new AuthFixture();

        self::assertTrue((new RememberMeFixture($fixture))->createService()->remember(AuthFixture::ACCOUNT_ID));

        $cookie = $fixture->getRememberCookie();

        self::assertMatchesRegularExpression('/^[0-9a-f]{32}:[0-9a-f]{64}$/', $cookie);
        self::assertEquals(
            (new RememberMeFixture($fixture))->createConfiguration()->cookieConfiguration,
            $fixture->getCookieService()->getLastConfiguration(),
        );
        self::assertEquals(
            new RememberToken(
                substr($cookie, 0, 32),
                AuthFixture::ACCOUNT_ID,
                hash('sha256', substr($cookie, 33)),
                0,
                AuthFixture::START_TIME + AuthFixture::REMEMBER_LIFETIME,
            ),
            (new RememberMeFixture($fixture))->createTokenStorage()->fetch(substr($cookie, 0, 32)),
        );
    }

    public function testTheTokenWorksUntilItExpiresFromEveryTab(): void
    {
        $fixture = new AuthFixture();
        $service = (new RememberMeFixture($fixture))->createService();
        $service->remember(AuthFixture::ACCOUNT_ID);

        self::assertSame(AuthFixture::ACCOUNT_ID, $service->restore());
        // Another tab, at the same time.
        self::assertSame(AuthFixture::ACCOUNT_ID, (new RememberMeFixture($fixture))->createService()->restore());

        $fixture->advanceClock(AuthFixture::REMEMBER_LIFETIME);

        self::assertNull($service->restore());
        self::assertSame('', $fixture->getRememberCookie());
    }

    public function testAWrongValidatorRemovesTheTokenAndTheCookie(): void
    {
        $fixture = new AuthFixture();
        $service = (new RememberMeFixture($fixture))->createService();
        $service->remember(AuthFixture::ACCOUNT_ID);
        $cookie = $fixture->getRememberCookie();
        $fixture->getCookieService()->send(AuthFixture::REMEMBER_COOKIE, substr($cookie, 0, 33) . str_repeat('0', 64));

        self::assertNull($service->restore());
        self::assertSame('', $fixture->getRememberCookie());

        $fixture->getCookieService()->send(AuthFixture::REMEMBER_COOKIE, $cookie);

        self::assertNull($service->restore());
    }

    public function testLoggingOutEverywhereEndsTheToken(): void
    {
        $fixture = new AuthFixture();
        $service = (new RememberMeFixture($fixture))->createService();
        $service->remember(AuthFixture::ACCOUNT_ID);
        $fixture->createStateStorage()->incrementEpoch(AuthFixture::ACCOUNT_ID);

        self::assertNull($service->restore());
    }

    public function testForgetDeletesTheTokenAndTheCookie(): void
    {
        $fixture = new AuthFixture();
        $service = (new RememberMeFixture($fixture))->createService();
        $service->remember(AuthFixture::ACCOUNT_ID);
        $cookie = $fixture->getRememberCookie();

        self::assertTrue($service->forget());
        self::assertSame('', $fixture->getRememberCookie());

        $fixture->getCookieService()->send(AuthFixture::REMEMBER_COOKIE, $cookie);

        self::assertNull($service->restore());
    }

    public function testAMissingOrMalformedCookieIsNoLogin(): void
    {
        $fixture = new AuthFixture();
        $service = (new RememberMeFixture($fixture))->createService();

        self::assertNull($service->restore());

        $fixture->getCookieService()->send(AuthFixture::REMEMBER_COOKIE, 'not:a token');

        self::assertNull($service->restore());

        $fixture->getCookieService()->sendArray();

        self::assertNull($service->restore());
    }

    public function testANewTokenRemovesTheAccountsExpiredTokens(): void
    {
        $fixture = new AuthFixture();
        $service = (new RememberMeFixture($fixture))->createService();
        $service->remember(AuthFixture::ACCOUNT_ID);
        $oldSelector = substr($fixture->getRememberCookie(), 0, 32);
        $fixture->advanceClock(AuthFixture::REMEMBER_LIFETIME);
        $service->remember(AuthFixture::ACCOUNT_ID);

        self::assertNull((new RememberMeFixture($fixture))->createTokenStorage()->fetch($oldSelector));
    }
}
