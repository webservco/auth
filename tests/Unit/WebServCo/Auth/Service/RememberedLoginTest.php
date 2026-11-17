<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\AuthFixture;
use Tests\Unit\Assets\FakeSecondFactor;
use Tests\Unit\Assets\RememberMeFixture;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\AuthenticationAttempt;
use WebServCo\Auth\Model\DataTransfer\LoginResult;
use WebServCo\Auth\Model\DataTransfer\PendingAuthentication;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberToken;
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Auth\Model\RememberLogin;
use WebServCo\Auth\Model\SecondFactorPolicy;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\LoginService;
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\RememberMeService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Auth\Service\Storage\PDORememberTokenStorage;

use function array_values;

/**
 * Remember-me through AuthenticationService and LoginService. "The browser closed" is a session without the login.
 */
#[CoversClass(AuthenticationService::class)]
#[CoversClass(LoginService::class)]
#[UsesClass(Account::class)]
#[UsesClass(AccountCredential::class)]
#[UsesClass(AccountState::class)]
#[UsesClass(AccountTableConfiguration::class)]
#[UsesClass(AuthenticationAttempt::class)]
#[UsesClass(CredentialVerificationService::class)]
#[UsesClass(LoginResult::class)]
#[UsesClass(PasswordHashService::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDOAccountStorage::class)]
#[UsesClass(PDORememberTokenStorage::class)]
#[UsesClass(PendingAuthentication::class)]
#[UsesClass(RealmConfiguration::class)]
#[UsesClass(RememberMeConfiguration::class)]
#[UsesClass(RememberMeService::class)]
#[UsesClass(RememberToken::class)]
final class RememberedLoginTest extends TestCase
{
    public function testARememberedLoginOutlivesTheSession(): void
    {
        $fixture = new AuthFixture();
        $service = $this->createService($fixture);
        $service->login(AuthFixture::ACCOUNT_ID, RememberLogin::Yes);
        $this->closeBrowser($fixture);

        self::assertSame(AuthFixture::ACCOUNT_ID, $this->getAccountId($service));
        self::assertSame(2, $fixture->getSessionService()->getRegenerations());

        // The session holds the login again: the cookie isn't needed any more.
        $fixture->getCookieService()->sendArray();

        self::assertSame(AuthFixture::ACCOUNT_ID, $this->getAccountId($service));
    }

    public function testWithoutRememberLoginOrRememberMeNoCookieIsSet(): void
    {
        $fixture = new AuthFixture();
        $this->createService($fixture)->login(AuthFixture::ACCOUNT_ID);
        $fixture->createAuthenticationService()->login(AuthFixture::ACCOUNT_ID, RememberLogin::Yes);

        self::assertSame('', $fixture->getRememberCookie());
    }

    public function testAfterASessionTimeoutTheCookieLogsInAgain(): void
    {
        $fixture = new AuthFixture();
        $service = $this->createService($fixture);
        $service->login(AuthFixture::ACCOUNT_ID, RememberLogin::Yes);
        $fixture->advanceClock(1800);

        self::assertSame(AuthFixture::ACCOUNT_ID, $this->getAccountId($service));
    }

    public function testLogoutEndsTheRememberedLogin(): void
    {
        $fixture = new AuthFixture();
        $service = $this->createService($fixture);
        $service->login(AuthFixture::ACCOUNT_ID, RememberLogin::Yes);
        $cookie = $fixture->getRememberCookie();
        $service->logout();

        self::assertTrue($fixture->getSessionService()->isDestroyed());
        self::assertSame('', $fixture->getRememberCookie());

        // A copy of the cookie made before the logout.
        $fixture->getCookieService()->send(AuthFixture::REMEMBER_COOKIE, $cookie);

        self::assertNull($service->getAuthenticatedAccount());
    }

    public function testLogoutEverywhereEndsRememberedLogins(): void
    {
        $fixture = new AuthFixture();
        $service = $this->createService($fixture);
        $service->login(AuthFixture::ACCOUNT_ID, RememberLogin::Yes);
        $service->logoutEverywhere(AuthFixture::ACCOUNT_ID);

        self::assertNull($service->getAuthenticatedAccount());
        self::assertSame('', $fixture->getRememberCookie());
    }

    public function testADisabledAccountIsNotRestored(): void
    {
        $fixture = new AuthFixture();
        $service = $this->createService($fixture);
        $service->login(AuthFixture::ACCOUNT_ID, RememberLogin::Yes);
        $this->closeBrowser($fixture);
        $fixture->deactivateAccount();

        self::assertNull($service->getAuthenticatedAccount());
        self::assertSame('', $fixture->getRememberCookie());
    }

    public function testThePasswordStepAloneSetsNoCookie(): void
    {
        $fixture = new AuthFixture();
        $loginService = $this->createLoginService($fixture, new FakeSecondFactor('totp', ['42']));
        $result = $loginService->login('editor', 'right password', RememberLogin::Yes);

        self::assertSame(LoginStatus::SecondFactorRequired, $result->status);
        self::assertSame('', $fixture->getRememberCookie());
        self::assertSame(LoginStatus::LoggedIn, $loginService->completeSecondFactor('totp', '123456')->status);

        $this->closeBrowser($fixture);

        self::assertSame(AuthFixture::ACCOUNT_ID, $this->getAccountId($this->createService($fixture)));
    }

    public function testWithoutASecondFactorThePasswordSetsTheCookie(): void
    {
        $fixture = new AuthFixture();
        $result = $this->createLoginService($fixture)->login('editor', 'right password', RememberLogin::Yes);

        self::assertSame(LoginStatus::LoggedIn, $result->status);
        self::assertNotSame('', $fixture->getRememberCookie());
    }

    private function closeBrowser(AuthFixture $fixture): void
    {
        $fixture->getSessionService()->unsetSessionDataItem('auth.admin');
    }

    private function createLoginService(AuthFixture $fixture, FakeSecondFactor ...$secondFactors): LoginService
    {
        return new LoginService(
            $this->createService($fixture),
            new CredentialVerificationService(
                $fixture->createAccountStorage(),
                $fixture->createStateStorage(),
                $fixture->getClock(),
                new PasswordHashService(4),
            ),
            SecondFactorPolicy::Optional,
            array_values($secondFactors),
        );
    }

    /**
     * Read again on each call: the login changes between calls.
     *
     * @phpstan-impure
     */
    private function getAccountId(AuthenticationService $service): ?string
    {
        return $service->getAuthenticatedAccount()?->id;
    }

    private function createService(AuthFixture $fixture): AuthenticationService
    {
        return $fixture->createAuthenticationService('admin', (new RememberMeFixture($fixture))->createService());
    }
}
