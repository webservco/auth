<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service\Storage;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\SqlitePDOContainer;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;

use function str_repeat;

#[CoversClass(PDOAccountStateStorage::class)]
#[UsesClass(AccountState::class)]
final class PDOAccountStateStorageTest extends TestCase
{
    private const string ACCOUNT_ID = '42';

    public function testAnAccountWithoutARowHasAZeroState(): void
    {
        self::assertEquals(new AccountState(0, null, 0, null), $this->createStorage()->fetch(self::ACCOUNT_ID));
    }

    public function testFailuresAreCountedAndLocked(): void
    {
        $storage = $this->createStorage();

        self::assertSame(1, $storage->recordFailure(self::ACCOUNT_ID));
        self::assertSame(2, $storage->recordFailure(self::ACCOUNT_ID));

        $storage->lock(self::ACCOUNT_ID, 5000);

        self::assertEquals(new AccountState(2, 5000, 0, null), $storage->fetch(self::ACCOUNT_ID));
    }

    public function testASuccessClearsTheFailuresAndRecordsTheLogin(): void
    {
        $storage = $this->createStorage();
        $storage->recordFailure(self::ACCOUNT_ID);
        $storage->lock(self::ACCOUNT_ID, 5000);
        $storage->recordSuccess(self::ACCOUNT_ID, 6000);

        self::assertEquals(new AccountState(0, null, 0, 6000), $storage->fetch(self::ACCOUNT_ID));
    }

    public function testTheEpochGrows(): void
    {
        $storage = $this->createStorage();

        self::assertSame(1, $storage->incrementEpoch(self::ACCOUNT_ID));
        self::assertSame(2, $storage->incrementEpoch(self::ACCOUNT_ID));
    }

    public function testRealmsAreIsolated(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $adminStorage = $this->createStorage('admin', $pdoContainer);
        $customerStorage = $this->createStorage('customer', $pdoContainer);
        $adminStorage->incrementEpoch(self::ACCOUNT_ID);

        self::assertSame(0, $customerStorage->fetch(self::ACCOUNT_ID)->epoch);
        self::assertSame(1, $adminStorage->fetch(self::ACCOUNT_ID)->epoch);
    }

    public function testAnAccountIdLongerThanTheColumnIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The account id must be 1 to 64 characters long.');

        $this->createStorage()->recordFailure(str_repeat('1', 65));
    }

    public function testAnInvalidRealmIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The realm must be 1 to 32 letters, digits, "_" or "-".');

        $this->createStorage('admin|customer')->fetch(self::ACCOUNT_ID);
    }

    public function testAnInvalidTableNameIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Invalid table name.');

        $storage = new PDOAccountStateStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            new SqlitePDOContainer(),
            'admin',
            'state; DROP TABLE x',
        );
        $storage->fetch(self::ACCOUNT_ID);
    }

    private function createStorage(
        string $realm = 'admin',
        SqlitePDOContainer $pdoContainer = new SqlitePDOContainer(),
    ): PDOAccountStateStorage {
        return new PDOAccountStateStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
            $realm,
        );
    }
}
