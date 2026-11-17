<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\AuthFixture;
use Tests\Unit\Assets\FakeSecondFactor;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\AuthenticationAttempt;
use WebServCo\Auth\Model\DataTransfer\LoginResult;
use WebServCo\Auth\Model\DataTransfer\PendingAuthentication;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Auth\Model\SecondFactorPolicy;
use WebServCo\Auth\Model\SecondFactorResult;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\LoginService;
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;

use function array_values;

/**
 * The password step and the second factor. The setup step is in LoginServiceSetupTest.
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
#[UsesClass(PasswordHashService::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDOAccountStorage::class)]
#[UsesClass(PendingAuthentication::class)]
#[UsesClass(RealmConfiguration::class)]
final class LoginServiceTest extends TestCase
{
    private const string PASSWORD = 'right password';

    public function testWithoutASecondFactorTheRightPasswordLogsIn(): void
    {
        $fixture = new AuthFixture();

        $service = $this->createService($fixture);

        self::assertSame(LoginStatus::LoggedIn, $service->login('editor', self::PASSWORD)->status);
        self::assertSame('42', $this->getLoggedInAccountId($fixture));
    }

    public function testAWrongPasswordAndThrottlingAreReported(): void
    {
        $service = $this->createService(new AuthFixture());

        for ($attempt = 1; $attempt <= 5; $attempt += 1) {
            self::assertSame(LoginStatus::InvalidCredentials, $service->login('editor', 'wrong')->status);
        }

        self::assertEquals(new LoginResult(LoginStatus::Throttled, 60), $service->login('editor', self::PASSWORD));
    }

    public function testAnAccountWithAFactorMustPassItWithItsOwnAttempt(): void
    {
        $fixture = new AuthFixture();
        $totp = new FakeSecondFactor('totp', ['42']);
        $service = $this->createService($fixture, $totp);

        self::assertSame(LoginStatus::SecondFactorRequired, $service->login('editor', self::PASSWORD)->status);
        self::assertNull($this->getLoggedInAccountId($fixture));
        self::assertSame(['totp'], $service->getSecondFactorMethods());

        $attemptId = $this->getAttemptId($fixture);

        self::assertSame('challenge:' . $attemptId, $service->startSecondFactor('totp'));
        self::assertSame(LoginStatus::LoggedIn, $service->completeSecondFactor('totp', '123456')->status);
        self::assertSame(['challenge 42 ' . $attemptId, 'verify 42 ' . $attemptId], $totp->getCalls());
        self::assertSame('42', $this->getLoggedInAccountId($fixture));
    }

    public function testAWrongOrLockedAnswerKeepsTheLoginPending(): void
    {
        $fixture = new AuthFixture();
        $rejecting = $this->createService($fixture, new FakeSecondFactor('totp', ['42']));
        $rejecting->login('editor', self::PASSWORD);

        self::assertSame(LoginStatus::SecondFactorRejected, $rejecting->completeSecondFactor('totp', '000000')->status);
        self::assertSame(['totp'], $rejecting->getSecondFactorMethods());

        $locking = $this->createService($fixture, new FakeSecondFactor('totp', ['42'], SecondFactorResult::Locked));

        self::assertSame(LoginStatus::SecondFactorLocked, $locking->completeSecondFactor('totp', '000000')->status);
        self::assertNull($this->getLoggedInAccountId($fixture));
    }

    public function testOnlyMethodsEnabledForTheAccountAreOffered(): void
    {
        $service = $this->createService(
            new AuthFixture(),
            new FakeSecondFactor('totp', ['42']),
            new FakeSecondFactor('email', []),
        );
        $service->login('editor', self::PASSWORD);

        self::assertSame(['totp'], $service->getSecondFactorMethods());
        self::assertNull($service->startSecondFactor('email'));
        self::assertSame(LoginStatus::MethodNotAvailable, $service->completeSecondFactor('email', '123456')->status);
        self::assertSame(LoginStatus::MethodNotAvailable, $service->completeSecondFactor('other', '123456')->status);
    }

    public function testWithoutAPendingLoginNothingCompletes(): void
    {
        $fixture = new AuthFixture();
        $service = $this->createService($fixture, new FakeSecondFactor('totp', ['42']));

        self::assertSame([], $service->getSecondFactorMethods());
        self::assertNull($service->startSecondFactor('totp'));
        self::assertSame(LoginStatus::NoPendingLogin, $service->completeSecondFactor('totp', '123456')->status);

        $service->login('editor', self::PASSWORD);
        $fixture->advanceClock(300);

        self::assertSame(LoginStatus::NoPendingLogin, $service->completeSecondFactor('totp', '123456')->status);
    }

    public function testWithTheOptionalPolicyAnAccountWithoutAFactorLogsIn(): void
    {
        $service = $this->createService(new AuthFixture(), new FakeSecondFactor('totp', ['43']));

        self::assertSame(LoginStatus::LoggedIn, $service->login('editor', self::PASSWORD)->status);
    }

    private function createService(AuthFixture $fixture, FakeSecondFactor ...$secondFactors): LoginService
    {
        return new LoginService(
            $fixture->createAuthenticationService(),
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

    private function getAttemptId(AuthFixture $fixture): string
    {
        $pendingAuthentication = $fixture->createAuthenticationService()->getPendingAuthentication();

        if ($pendingAuthentication === null) {
            self::fail('There is no pending login.');
        }

        return $pendingAuthentication->attemptId;
    }

    /**
     * Read again on each call: the login changes between calls.
     *
     * @phpstan-impure
     */
    private function getLoggedInAccountId(AuthFixture $fixture): ?string
    {
        return $fixture->createAuthenticationService()->getAuthenticatedAccount()?->id;
    }
}
