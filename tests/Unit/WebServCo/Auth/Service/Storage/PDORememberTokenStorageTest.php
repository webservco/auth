<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service\Storage;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\SqlitePDOContainer;
use WebServCo\Auth\Model\DataTransfer\RememberToken;
use WebServCo\Auth\Service\Storage\PDORememberTokenStorage;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;

use function str_repeat;

#[CoversClass(PDORememberTokenStorage::class)]
#[UsesClass(RememberToken::class)]
final class PDORememberTokenStorageTest extends TestCase
{
    public function testATokenBelongsToItsRealm(): void
    {
        $pdoContainer = new SqlitePDOContainer();
        $admin = $this->createStorage($pdoContainer, 'admin');
        $customer = $this->createStorage($pdoContainer, 'customer');
        $token = $this->createToken('a', '42', 2000);
        $admin->save($token, 1000);

        self::assertNull($customer->fetch($token->selector));
        self::assertFalse($customer->delete($token->selector));
        self::assertEquals($token, $admin->fetch($token->selector));
        self::assertTrue($admin->delete($token->selector));
        self::assertFalse($admin->delete($token->selector));
    }

    public function testOnlyTheAccountsExpiredTokensAreRemoved(): void
    {
        $storage = $this->createStorage(new SqlitePDOContainer(), 'admin');
        $storage->save($this->createToken('a', '42', 1500), 1000);
        $storage->save($this->createToken('b', '42', 2500), 1000);
        $storage->save($this->createToken('c', '43', 1500), 1000);
        $storage->deleteExpired('42', 2000);

        self::assertNull($storage->fetch(str_repeat('a', 32)));
        self::assertNotNull($storage->fetch(str_repeat('b', 32)));
        self::assertNotNull($storage->fetch(str_repeat('c', 32)));
    }

    public function testAnAccountIdLongerThanTheColumnIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The account id must be 1 to 64 characters long.');

        $this->createStorage(new SqlitePDOContainer(), 'admin')->save(
            $this->createToken('a', str_repeat('1', 65), 2000),
            1000,
        );
    }

    public function testAnInvalidRealmIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The realm must be 1 to 32 letters, digits, "_" or "-".');

        $this->createStorage(new SqlitePDOContainer(), 'admin.customer');
    }

    public function testAnInvalidTableNameIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Invalid table name.');

        $storage = new PDORememberTokenStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            new SqlitePDOContainer(),
            'admin',
            'auth_remember_token; DROP TABLE user_account',
        );

        self::assertNull($storage->fetch(str_repeat('a', 32)));
    }

    private function createStorage(SqlitePDOContainer $pdoContainer, string $realm): PDORememberTokenStorage
    {
        return new PDORememberTokenStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $pdoContainer,
            $realm,
        );
    }

    private function createToken(string $letter, string $accountId, int $expiresAt): RememberToken
    {
        return new RememberToken(str_repeat($letter, 32), $accountId, str_repeat('f', 64), 0, $expiresAt);
    }
}
