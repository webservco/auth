<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Model\DataTransfer;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;

#[CoversClass(AccountTableConfiguration::class)]
final class AccountTableConfigurationTest extends TestCase
{
    public function testAValidMappingIsKept(): void
    {
        $configuration = new AccountTableConfiguration(
            'user_account',
            'id',
            'username',
            'password',
            'status',
            'on',
            ['role'],
        );

        self::assertSame('user_account', $configuration->tableName);
        self::assertSame(['role'], $configuration->attributeColumns);
    }

    /**
     * @param list<string> $attributeColumns
     */
    #[DataProvider('invalidNameProvider')]
    public function testAnInvalidNameIsRejected(string $tableName, string $activeColumn, array $attributeColumns): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Invalid table or column name.');

        $configuration = new AccountTableConfiguration(
            $tableName,
            'id',
            'username',
            'password',
            $activeColumn,
            'on',
            $attributeColumns,
        );
        self::assertSame('', $configuration->tableName);
    }

    public function testAnActiveColumnNeedsAValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Set both the active column and its value, or neither.');

        $configuration = new AccountTableConfiguration('user_account', 'id', 'username', 'password', 'status');
        self::assertSame('', $configuration->tableName);
    }

    /**
     * @return array<string,array{0:string,1:string,2:list<string>}>
     */
    public static function invalidNameProvider(): array
    {
        return [
            'attribute with a dash' => ['user_account', 'status', ['user-role']],
            'injection in the table name' => ['user_account; DROP TABLE x', 'status', []],
            'quoted active column' => ['user_account', '`status`', []],
            'space in the table name' => ['user account', 'status', []],
        ];
    }
}
