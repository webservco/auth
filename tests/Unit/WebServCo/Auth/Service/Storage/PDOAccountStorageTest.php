<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service\Storage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\SqlitePDOContainer;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;

#[CoversClass(PDOAccountStorage::class)]
#[UsesClass(Account::class)]
#[UsesClass(AccountCredential::class)]
#[UsesClass(AccountTableConfiguration::class)]
final class PDOAccountStorageTest extends TestCase
{
    public function testFetchCredentialReturnsTheIdAsTextAndTheHash(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', 'hash-42');

        self::assertEquals(
            new AccountCredential('42', 'hash-42'),
            $this->createStorage($pdoContainer)->fetchCredential('editor'),
        );
    }

    public function testFetchAccountReturnsTheLoginAndTheAttributes(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', 'hash-42');

        self::assertEquals(
            new Account('42', 'editor', ['role' => 'editor']),
            $this->createStorage($pdoContainer)->fetchAccount('42'),
        );
    }

    public function testInactiveAndUnknownAccountsAreNotReturned(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', 'hash-42', 'off');
        $storage = $this->createStorage($pdoContainer);

        self::assertNull($storage->fetchCredential('editor'));
        self::assertNull($storage->fetchAccount('42'));
        self::assertNull($storage->fetchCredential('unknown'));
    }

    public function testALoginOfTwoActiveAccountsIsRefused(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', 'hash-42');
        $pdoContainer->insertUser(43, 'editor', 'hash-43');

        self::assertNull($this->createStorage($pdoContainer)->fetchCredential('editor'));
    }

    public function testUpdatePasswordHashReplacesTheHash(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', 'old-hash');
        $storage = $this->createStorage($pdoContainer);
        $storage->updatePasswordHash('42', 'new-hash');

        self::assertSame('new-hash', $storage->fetchCredential('editor')?->passwordHash);
    }

    public function testWithoutAnActiveColumnEveryAccountCanLogIn(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->insertUser(42, 'editor', 'hash-42', 'off');
        $storage = new PDOAccountStorage(
            new AccountTableConfiguration('user_account', 'id', 'username', 'password'),
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
        );

        self::assertEquals(new Account('42', 'editor', []), $storage->fetchAccount('42'));
    }

    public function testAnAccountWithoutAPasswordHasAnEmptyHash(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $pdoContainer->getPDO()->exec(
            "INSERT INTO user_account (id, username, password, status) VALUES (43, 'invited', NULL, 'on')",
        );

        self::assertEquals(
            new AccountCredential('43', ''),
            $this->createStorage($pdoContainer)->fetchCredential('invited'),
        );
    }

    private function createStorage(SqlitePDOContainer $pdoContainer): PDOAccountStorage
    {
        return new PDOAccountStorage(
            new AccountTableConfiguration('user_account', 'id', 'username', 'password', 'status', 'on', ['role']),
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
        );
    }
}
