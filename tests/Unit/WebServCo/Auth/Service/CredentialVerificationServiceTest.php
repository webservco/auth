<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\FixedClock;
use Tests\Unit\Assets\Md5LegacyPasswordVerifier;
use Tests\Unit\Assets\SqlitePDOContainer;
use WebServCo\Auth\Model\AuthenticationAttemptResult;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\AuthenticationAttempt;
use WebServCo\Auth\Service\CredentialVerificationService;
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;

use function md5;
use function password_hash;

use const PASSWORD_BCRYPT;

/**
 * bcrypt cost 4 throughout, to keep the tests fast.
 */
#[CoversClass(CredentialVerificationService::class)]
#[UsesClass(AccountCredential::class)]
#[UsesClass(AccountState::class)]
#[UsesClass(AccountTableConfiguration::class)]
#[UsesClass(AuthenticationAttempt::class)]
#[UsesClass(PasswordHashService::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDOAccountStorage::class)]
final class CredentialVerificationServiceTest extends TestCase
{
    private const string PASSWORD = 'right password';
    private const int START_TIME = 1_800_000_000;

    public function testTheRightPasswordSucceeds(): void
    {
        $pdoContainer = $this->createContainer($this->hashPassword(4));

        self::assertEquals(
            new AuthenticationAttempt(AuthenticationAttemptResult::Success, '42', 0),
            $this->createService($pdoContainer)->verifyCredentials('editor', self::PASSWORD),
        );
        self::assertSame(self::START_TIME, $this->createStateStorage($pdoContainer)->fetch('42')->lastLoginAt);
    }

    public function testUnknownLoginWrongPasswordAndInactiveAccountLookTheSame(): void
    {
        $invalid = new AuthenticationAttempt(AuthenticationAttemptResult::InvalidCredentials, null, 0);
        $pdoContainer = $this->createContainer($this->hashPassword(4));
        $pdoContainer->insertUser(43, 'inactive', $this->hashPassword(4), 'off');
        $service = $this->createService($pdoContainer);

        self::assertEquals($invalid, $service->verifyCredentials('unknown', self::PASSWORD));
        self::assertEquals($invalid, $service->verifyCredentials('editor', 'wrong password'));
        self::assertEquals($invalid, $service->verifyCredentials('inactive', self::PASSWORD));
    }

    public function testFromTheFifthFailureTheAccountWaitsEvenWithTheRightPassword(): void
    {
        $clock = new FixedClock(self::START_TIME);
        $service = $this->createService($this->createContainer($this->hashPassword(4)), $clock);

        for ($attempt = 1; $attempt <= 5; $attempt += 1) {
            $service->verifyCredentials('editor', 'wrong password');
        }

        self::assertEquals(
            new AuthenticationAttempt(AuthenticationAttemptResult::Throttled, null, 60),
            $service->verifyCredentials('editor', self::PASSWORD),
        );

        $clock->advance(60);

        self::assertSame(AuthenticationAttemptResult::Success, $this->verify($service, self::PASSWORD));
    }

    public function testTheWaitDoublesUpToFifteenMinutesAndNeverBecomesPermanent(): void
    {
        $clock = new FixedClock(self::START_TIME);
        $pdoContainer = $this->createContainer($this->hashPassword(4));
        $service = $this->createService($pdoContainer, $clock);
        $waits = [];

        for ($attempt = 1; $attempt <= 10; $attempt += 1) {
            $service->verifyCredentials('editor', 'wrong password');
            $lockedUntil = $this->createStateStorage($pdoContainer)->fetch('42')->lockedUntil;
            $waits[] = $lockedUntil === null
                ? 0
                : $lockedUntil - $clock->now()->getTimestamp();
            $clock->advance(900);
        }

        self::assertSame([0, 0, 0, 0, 60, 120, 240, 480, 900, 900], $waits);
        self::assertSame(AuthenticationAttemptResult::Success, $this->verify($service, self::PASSWORD));
    }

    public function testALegacyHashIsAcceptedOnceThenReplaced(): void
    {
        $pdoContainer = $this->createContainer(md5(self::PASSWORD));
        $legacyPasswordVerifier = new Md5LegacyPasswordVerifier();
        $service = $this->createService($pdoContainer, new FixedClock(self::START_TIME), $legacyPasswordVerifier);
        $firstLogin = $this->verify($service, self::PASSWORD);
        $secondLogin = $this->verify($service, self::PASSWORD);

        self::assertSame(
            [AuthenticationAttemptResult::Success, AuthenticationAttemptResult::Success],
            [$firstLogin, $secondLogin],
        );
        self::assertSame(1, $legacyPasswordVerifier->getCalls());
        self::assertTrue((new PasswordHashService(4))->isPasswordHash($this->fetchStoredHash($pdoContainer)));
    }

    public function testALegacyHashWithoutAVerifierIsRefused(): void
    {
        self::assertSame(
            AuthenticationAttemptResult::InvalidCredentials,
            $this->verify($this->createService($this->createContainer(md5(self::PASSWORD))), self::PASSWORD),
        );
    }

    public function testAHashWithOutdatedSettingsIsReplacedAtLogin(): void
    {
        $pdoContainer = $this->createContainer($this->hashPassword(5));
        $this->createService($pdoContainer)->verifyCredentials('editor', self::PASSWORD);

        self::assertFalse((new PasswordHashService(4))->needsRehash($this->fetchStoredHash($pdoContainer)));
    }

    private function createContainer(string $passwordHash): SqlitePDOContainer
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', $passwordHash);

        return $pdoContainer;
    }

    private function createService(
        SqlitePDOContainer $pdoContainer,
        FixedClock $clock = new FixedClock(self::START_TIME),
        ?Md5LegacyPasswordVerifier $legacyPasswordVerifier = null,
    ): CredentialVerificationService {
        return new CredentialVerificationService(
            $this->createAccountStorage($pdoContainer),
            $this->createStateStorage($pdoContainer),
            $clock,
            new PasswordHashService(4),
            $legacyPasswordVerifier,
        );
    }

    private function createAccountStorage(SqlitePDOContainer $pdoContainer): PDOAccountStorage
    {
        return new PDOAccountStorage(
            new AccountTableConfiguration('user_account', 'id', 'username', 'password', 'status', 'on'),
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
        );
    }

    private function createStateStorage(SqlitePDOContainer $pdoContainer): PDOAccountStateStorage
    {
        return new PDOAccountStateStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
            'admin',
        );
    }

    private function fetchStoredHash(SqlitePDOContainer $pdoContainer): string
    {
        $credential = $this->createAccountStorage($pdoContainer)->fetchCredential('editor');

        if ($credential === null) {
            self::fail('The account is missing.');
        }

        return $credential->passwordHash;
    }

    private function hashPassword(int $cost): string
    {
        return password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => $cost]);
    }

    private function verify(CredentialVerificationService $service, string $password): AuthenticationAttemptResult
    {
        return $service->verifyCredentials('editor', $password)->result;
    }
}
