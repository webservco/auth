<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;

use function password_hash;

use const PASSWORD_BCRYPT;

/**
 * One active account (42, "editor", password "right password"), an in-memory session and a fixed clock.
 */
final readonly class AuthFixture
{
    public const string ACCOUNT_ID = '42';

    public const int START_TIME = 1_800_000_000;

    private FixedClock $clock;
    private SqlitePDOContainer $pdoContainer;
    private InMemorySessionService $sessionService;

    public function __construct()
    {
        $this->clock = new FixedClock(self::START_TIME);
        $this->pdoContainer = new SqlitePDOContainer();
        $this->pdoContainer->insertUser(42, 'editor', password_hash('right password', PASSWORD_BCRYPT, ['cost' => 4]));
        $this->sessionService = new InMemorySessionService();
    }

    public function advanceClock(int $seconds): void
    {
        $this->clock->advance($seconds);
    }

    public function createAccountStorage(): PDOAccountStorage
    {
        return new PDOAccountStorage(
            new AccountTableConfiguration('user_account', 'id', 'username', 'password', 'status', 'on', ['role']),
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $this->pdoContainer,
        );
    }

    public function createAuthenticationService(string $realm = 'admin'): AuthenticationService
    {
        return new AuthenticationService(
            $this->createAccountStorage(),
            $this->createStateStorage($realm),
            $this->clock,
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            new RealmConfiguration($realm),
            $this->sessionService,
        );
    }

    public function createStateStorage(string $realm = 'admin'): PDOAccountStateStorage
    {
        return new PDOAccountStateStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $this->pdoContainer,
            $realm,
        );
    }

    public function deactivateAccount(): bool
    {
        $statement = $this->pdoContainer->getPDOService()->prepareStatement(
            $this->pdoContainer->getPDO(),
            "UPDATE user_account SET status = 'off' WHERE id = 42",
        );

        return $statement->execute();
    }

    public function getClock(): FixedClock
    {
        return $this->clock;
    }

    public function getSessionService(): InMemorySessionService
    {
        return $this->sessionService;
    }
}
