<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use InvalidArgumentException;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;

use function preg_match;

/**
 * The application's account table. The names go into the SQL, so each one is validated; values are always bound.
 */
final readonly class AccountTableConfiguration implements DataTransferInterface
{
    /**
     * @param ?string $activeColumn with $activeValue: only rows where the column has this value can log in
     * @param list<string> $attributeColumns extra columns returned with the account, for example a role
     */
    public function __construct(
        public string $tableName,
        public string $idColumn,
        public string $loginColumn,
        public string $passwordColumn,
        public ?string $activeColumn = null,
        public ?string $activeValue = null,
        public array $attributeColumns = [],
    ) {
        if (($activeColumn === null) !== ($activeValue === null)) {
            throw new InvalidArgumentException('Set both the active column and its value, or neither.');
        }

        $identifiers = [$tableName, $idColumn, $loginColumn, $passwordColumn, ...$attributeColumns];

        if ($activeColumn !== null) {
            $identifiers[] = $activeColumn;
        }

        foreach ($identifiers as $identifier) {
            $this->assertIdentifier($identifier);
        }
    }

    private function assertIdentifier(string $identifier): bool
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}\z/', $identifier) !== 1) {
            throw new InvalidArgumentException('Invalid table or column name.');
        }

        return true;
    }
}
