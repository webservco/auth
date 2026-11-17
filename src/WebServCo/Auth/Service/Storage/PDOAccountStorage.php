<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service\Storage;

use Override;
use PDOStatement;
use WebServCo\Auth\Contract\Storage\AccountStorageInterface;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountCredential;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;

use function implode;
use function sprintf;

/**
 * The names come validated from AccountTableConfiguration and are quoted with backticks (SQLite accepts them too).
 * A login that matches more than one active row is refused: the account would be ambiguous.
 */
final readonly class PDOAccountStorage implements AccountStorageInterface
{
    public function __construct(
        private AccountTableConfiguration $configuration,
        private DataExtractionContainerInterface $dataExtractionContainer,
        private PDOContainerInterface $pdoContainer,
    ) {
    }

    #[Override]
    public function fetchAccount(string $accountId): ?Account
    {
        $row = $this->fetchSingleRow($this->getAccountColumns(), $this->configuration->idColumn, $accountId);

        if ($row === []) {
            return null;
        }

        $extraction = $this->dataExtractionContainer->getLooseArrayDataExtractionService();
        $attributes = [];

        foreach ($this->configuration->attributeColumns as $column) {
            $attributes[$column] = $row[$column] ?? null;
        }

        return new Account(
            $extraction->getString($row, 'auth_account_id'),
            $extraction->getString($row, 'auth_account_login'),
            $attributes,
        );
    }

    #[Override]
    public function fetchCredential(string $login): ?AccountCredential
    {
        $row = $this->fetchSingleRow(
            sprintf(
                '%s AS auth_account_id, %s AS auth_password_hash',
                $this->quote($this->configuration->idColumn),
                $this->quote($this->configuration->passwordColumn),
            ),
            $this->configuration->loginColumn,
            $login,
        );

        if ($row === []) {
            return null;
        }

        $extraction = $this->dataExtractionContainer->getLooseArrayDataExtractionService();

        return new AccountCredential(
            $extraction->getString($row, 'auth_account_id'),
            $extraction->getString($row, 'auth_password_hash'),
        );
    }

    #[Override]
    public function updatePasswordHash(string $accountId, string $passwordHash): bool
    {
        $statement = $this->prepare(
            sprintf(
                'UPDATE %s SET %s = ? WHERE %s = ?',
                $this->quote($this->configuration->tableName),
                $this->quote($this->configuration->passwordColumn),
                $this->quote($this->configuration->idColumn),
            ),
        );
        $statement->execute([$passwordHash, $accountId]);

        return true;
    }

    /**
     * The one active row where the column has the value; [] when there is none, or more than one.
     *
     * @return array<string,scalar|null>
     */
    private function fetchSingleRow(string $columns, string $whereColumn, string $value): array
    {
        $query = sprintf(
            'SELECT %s FROM %s WHERE %s = ?',
            $columns,
            $this->quote($this->configuration->tableName),
            $this->quote($whereColumn),
        );
        $parameters = [$value];
        $activeColumn = $this->configuration->activeColumn;

        if ($activeColumn !== null) {
            $query .= sprintf(' AND %s = ?', $this->quote($activeColumn));
            $parameters[] = (string) $this->configuration->activeValue;
        }

        $statement = $this->prepare($query . ' LIMIT 2');
        $statement->execute($parameters);
        $pdoService = $this->pdoContainer->getPDOService();
        $row = $pdoService->fetchAssoc($statement);

        if ($pdoService->fetchAssoc($statement) !== []) {
            return [];
        }

        return $row;
    }

    private function getAccountColumns(): string
    {
        $columns = [
            sprintf('%s AS auth_account_id', $this->quote($this->configuration->idColumn)),
            sprintf('%s AS auth_account_login', $this->quote($this->configuration->loginColumn)),
        ];

        foreach ($this->configuration->attributeColumns as $column) {
            $columns[] = $this->quote($column);
        }

        return implode(', ', $columns);
    }

    private function prepare(string $query): PDOStatement
    {
        return $this->pdoContainer->getPDOService()->prepareStatement($this->pdoContainer->getPDO(), $query);
    }

    private function quote(string $identifier): string
    {
        return '`' . $identifier . '`';
    }
}
