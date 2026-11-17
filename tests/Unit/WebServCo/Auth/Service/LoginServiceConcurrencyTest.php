<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\AuthFixture;
use Tests\Unit\Assets\FakeSecondFactor;
use WebServCo\Auth\Contract\AuthenticationServiceInterface;
use WebServCo\Auth\Contract\CredentialVerificationServiceInterface;
use WebServCo\Auth\Contract\PasswordHashServiceInterface;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\AuthenticationAttempt;
use WebServCo\Auth\Model\DataTransfer\LoginResult;
use WebServCo\Auth\Model\DataTransfer\PendingAuthentication;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Auth\Model\PendingStep;
use WebServCo\Auth\Model\RememberLogin;
use WebServCo\Auth\Model\SecondFactorPolicy;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\LoginService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;

/**
 * Races that one in-memory session can't produce, simulated with stubs.
 */
#[CoversClass(LoginService::class)]
#[UsesClass(Account::class)]
#[UsesClass(AccountCredential::class)]
#[UsesClass(AccountState::class)]
#[UsesClass(AccountTableConfiguration::class)]
#[UsesClass(AuthenticationAttempt::class)]
#[UsesClass(AuthenticationService::class)]
#[UsesClass(CredentialVerificationService::class)]
#[UsesClass(LoginResult::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDOAccountStorage::class)]
#[UsesClass(PendingAuthentication::class)]
#[UsesClass(RealmConfiguration::class)]
final class LoginServiceConcurrencyTest extends TestCase
{
    public function testARefusedLoginAfterTheSecondFactorIsReported(): void
    {
        $authenticationService = self::createStub(AuthenticationServiceInterface::class);
        $authenticationService->method('getPendingAuthentication')->willReturn(
            new PendingAuthentication('42', 'attempt', PendingStep::SecondFactor, 1_800_000_000, RememberLogin::No, 0),
        );
        // The login was refused after the code was accepted.
        $authenticationService->method('login')->willReturn(false);

        $service = new LoginService(
            $authenticationService,
            self::createStub(CredentialVerificationServiceInterface::class),
            SecondFactorPolicy::Optional,
            [new FakeSecondFactor('totp', ['42'])],
        );

        self::assertSame(LoginStatus::NoPendingLogin, $service->completeSecondFactor('totp', '123456')->status);
    }

    public function testLoggingOutEverywhereDuringThePasswordCheckRefusesTheLogin(): void
    {
        $fixture = new AuthFixture();
        $passwordHashService = self::createStub(PasswordHashServiceInterface::class);
        $passwordHashService->method('isPasswordHash')->willReturn(true);
        $passwordHashService->method('verify')->willReturnCallback(
            static function () use ($fixture): bool {
                // The password changes, with "log out everywhere", while this request checks the old one.
                $fixture->createStateStorage()->incrementEpoch(AuthFixture::ACCOUNT_ID);

                return true;
            },
        );
        $service = new LoginService(
            $fixture->createAuthenticationService(),
            new CredentialVerificationService(
                $fixture->createAccountStorage(),
                $fixture->createStateStorage(),
                $fixture->getClock(),
                $passwordHashService,
            ),
            SecondFactorPolicy::Optional,
        );

        self::assertSame(LoginStatus::InvalidCredentials, $service->login('editor', 'right password')->status);
        self::assertNull($fixture->createAuthenticationService()->getAuthenticatedAccount());
    }
}
