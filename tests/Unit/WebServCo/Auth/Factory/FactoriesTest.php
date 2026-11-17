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
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\LoginService;
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Auth\Service\SystemClock;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;

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
#[UsesClass(RealmConfiguration::class)]
#[UsesClass(SystemClock::class)]
final class FactoriesTest extends TestCase
{
    public function testTheFactoriesBuildAWorkingLogin(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', password_hash('right password', PASSWORD_BCRYPT, ['cost' => 4]));
        $dataExtractionContainer = (new DataExtractionContainerFactory())->createDataExtractionContainer(false);
        $accountStorageFactory = new AccountStorageFactory($dataExtractionContainer, $pdoContainer);
        $authenticationServiceFactory = new AuthenticationServiceFactory(
            $accountStorageFactory,
            $dataExtractionContainer,
            new InMemorySessionService(),
        );
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
}
