<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Factory;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\InMemorySessionService;
use Tests\Unit\Assets\SqlitePDOContainer;
use WebServCo\Auth\Factory\AccountStorageFactory;
use WebServCo\Auth\Factory\AuthenticationServiceFactory;
use WebServCo\Auth\Factory\LoginServiceFactory;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\AuthenticationAttempt;
use WebServCo\Auth\Model\DataTransfer\LoginResult;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\LoginService;
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\RememberMeService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Auth\Service\Storage\PDORememberTokenStorage;
use WebServCo\Auth\Service\SystemClock;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;
use WebServCo\Session\Model\DataTransfer\CookieConfiguration;

use function password_hash;

use const PASSWORD_BCRYPT;

/**
 * The factories wired the way an application wires them, with one real login through them.
 */
#[CoversClass(AccountStorageFactory::class)]
#[CoversClass(AuthenticationServiceFactory::class)]
#[CoversClass(LoginServiceFactory::class)]
#[UsesClass(Account::class)]
#[UsesClass(AccountCredential::class)]
#[UsesClass(AccountState::class)]
#[UsesClass(AccountTableConfiguration::class)]
#[UsesClass(AuthenticationAttempt::class)]
#[UsesClass(AuthenticationService::class)]
#[UsesClass(CredentialVerificationService::class)]
#[UsesClass(LoginResult::class)]
#[UsesClass(LoginService::class)]
#[UsesClass(PasswordHashService::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDOAccountStorage::class)]
#[UsesClass(PDORememberTokenStorage::class)]
#[UsesClass(RealmConfiguration::class)]
#[UsesClass(RememberMeConfiguration::class)]
#[UsesClass(RememberMeService::class)]
#[UsesClass(SystemClock::class)]
final class FactoriesTest extends TestCase
{
    /**
     * Without a cookie in the request (none in the CLI), remember-me finds nothing; it must not break the login.
     */
    public function testRememberMeIsWiredWhenConfigured(): void
    {
        $accountStorageFactory = $this->createAccountStorageFactory();
        $authenticationServiceFactory = $this->createAuthenticationServiceFactory($accountStorageFactory);
        $realm = new RealmConfiguration('customer');
        $accountTable = new AccountTableConfiguration('user_account', 'id', 'username', 'password', 'status', 'on');
        $rememberMe = new RememberMeConfiguration(
            '__Host-remember',
            new CookieConfiguration(2_592_000, '/', '', true, true, 'Lax'),
        );
        $authenticationService = $authenticationServiceFactory->createAuthenticationService(
            $realm,
            $accountTable,
            $rememberMe,
        );

        self::assertNull($authenticationService->getAuthenticatedAccount());

        $loginService = (new LoginServiceFactory($accountStorageFactory, $authenticationServiceFactory))
            ->createLoginService($realm, $accountTable, rememberMeConfiguration: $rememberMe);

        self::assertSame(LoginStatus::LoggedIn, $loginService->login('editor', 'right password')->status);
        self::assertSame(
            '42',
            $authenticationServiceFactory->createAuthenticationService($realm, $accountTable, $rememberMe)
                ->getAuthenticatedAccount()?->id,
        );
    }

    public function testTheFactoriesBuildAWorkingLogin(): void
    {
        $accountStorageFactory = $this->createAccountStorageFactory();
        $authenticationServiceFactory = $this->createAuthenticationServiceFactory($accountStorageFactory);
        $realm = new RealmConfiguration('admin');
        $accountTable = new AccountTableConfiguration('user_account', 'id', 'username', 'password', 'status', 'on');
        $loginServiceFactory = new LoginServiceFactory($accountStorageFactory, $authenticationServiceFactory);

        self::assertSame(
            LoginStatus::LoggedIn,
            $loginServiceFactory->createLoginService($realm, $accountTable)->login('editor', 'right password')->status,
        );
        $authenticationService = $authenticationServiceFactory->createAuthenticationService($realm, $accountTable);

        self::assertSame('42', $authenticationService->getAuthenticatedAccount()?->id);
    }

    private function createAccountStorageFactory(): AccountStorageFactory
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', password_hash('right password', PASSWORD_BCRYPT, ['cost' => 4]));

        return new AccountStorageFactory(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
        );
    }

    private function createAuthenticationServiceFactory(
        AccountStorageFactory $accountStorageFactory,
    ): AuthenticationServiceFactory {
        return new AuthenticationServiceFactory(
            $accountStorageFactory,
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            new InMemorySessionService(),
        );
    }
}
