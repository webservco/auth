<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\LoginService;
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;

use function array_values;

/**
 * The Required policy: an account without a second factor sets one up before its login completes.
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
final class LoginServiceSetupTest extends TestCase
{
    public function testTheLoginCompletesOnlyOnceTheMethodIsEnabled(): void
    {
        $fixture = new AuthFixture();
        $totp = new FakeSecondFactor('totp', []);
        $service = $this->createService($fixture, $totp);

        self::assertSame(LoginStatus::SecondFactorSetupRequired, $service->login('editor', 'right password')->status);
        self::assertSame(['totp'], $service->getSecondFactorMethods());
        self::assertSame(LoginStatus::MethodNotAvailable, $service->completeSecondFactorSetup('totp')->status);

        // The application's setup page (for example webservco/mfa's enrollment) enables the method.
        $totp->enable('42');

        self::assertSame(LoginStatus::LoggedIn, $service->completeSecondFactorSetup('totp')->status);
        self::assertSame('42', $this->getLoggedInAccountId($fixture));
    }

    public function testASetupCanNotBeCompletedLikeAChallenge(): void
    {
        $service = $this->createService(new AuthFixture(), new FakeSecondFactor('totp', []));
        $service->login('editor', 'right password');

        self::assertNull($service->startSecondFactor('totp'));
        self::assertSame(LoginStatus::NoPendingLogin, $service->completeSecondFactor('totp', '123456')->status);
    }

    public function testAChallengeCanNotBeCompletedLikeASetup(): void
    {
        $service = $this->createService(new AuthFixture(), new FakeSecondFactor('totp', ['42']));
        $service->login('editor', 'right password');

        self::assertSame(LoginStatus::NoPendingLogin, $service->completeSecondFactorSetup('totp')->status);
    }

    public function testTheRequiredPolicyNeedsAMethod(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A required second factor needs at least one method.');

        self::assertSame([], $this->createService(new AuthFixture())->getSecondFactorMethods());
    }

    #[DataProvider('invalidMethodIdsProvider')]
    public function testMethodIdsMustBeUniqueAndSimple(string $firstId, string $secondId): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Second factor ids must be unique: 1 to 32 letters, digits, "_" or "-".');

        $service = $this->createService(
            new AuthFixture(),
            new FakeSecondFactor($firstId, []),
            new FakeSecondFactor($secondId, []),
        );
        self::assertSame([], $service->getSecondFactorMethods());
    }

    /**
     * @return array<string,array{0:string,1:string}>
     */
    public static function invalidMethodIdsProvider(): array
    {
        return [
            'duplicate' => ['totp', 'totp'],
            'space' => ['totp', 'email code'],
        ];
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
            SecondFactorPolicy::Required,
            array_values($secondFactors),
        );
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
