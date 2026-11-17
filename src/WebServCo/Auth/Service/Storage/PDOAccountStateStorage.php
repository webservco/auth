<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service\Storage;

use InvalidArgumentException;
use Override;
use PDOException;
use PDOStatement;
use WebServCo\Auth\Contract\Storage\AccountStateStorageInterface;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;

use function preg_match;
use function str_replace;
use function strlen;

/**
 * Table: `resources/auth.sql`. The table name replaces `{table}` in the SQL, so it is validated; values are bound.
 * Each change is one statement on a row that exists, so concurrent requests can't lose an update.
 */
final readonly class PDOAccountStateStorage implements AccountStateStorageInterface
{
    public function __construct(
        private DataExtractionContainerInterface $dataExtractionContainer,
        private PDOContainerInterface $pdoContainer,
        private string $realm,
        private string $tableName = 'auth_account_state',
    ) {
        if (preg_match('/^[A-Za-z0-9_-]{1,32}$/', $realm) !== 1) {
            throw new InvalidArgumentException('The realm must be 1 to 32 letters, digits, "_" or "-".');
        }

        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $tableName) !== 1) {
            throw new InvalidArgumentException('Invalid table name.');
        }
    }

    #[Override]
    public function fetch(string $accountId): AccountState
    {
        $row = $this->pdoContainer->getPDOService()->fetchAssoc(
            $this->execute(
                'SELECT failed_attempts, locked_until, epoch, last_login_at'
                . ' FROM {table} WHERE realm = ? AND account_id = ?',
                [$this->realm, $accountId],
            ),
        );

        if ($row === []) {
            return new AccountState(0, null, 0, null);
        }

        $extraction = $this->dataExtractionContainer->getStrictArrayDataExtractionService();

        return new AccountState(
            $extraction->getInt($row, 'failed_attempts'),
            $extraction->getNullableInt($row, 'locked_until'),
            $extraction->getInt($row, 'epoch'),
            $extraction->getNullableInt($row, 'last_login_at'),
        );
    }

    #[Override]
    public function incrementEpoch(string $accountId): int
    {
        $this->ensureRow($accountId);
        $this->execute(
            'UPDATE {table} SET epoch = epoch + 1 WHERE realm = ? AND account_id = ?',
            [$this->realm, $accountId],
        );

        return $this->fetch($accountId)->epoch;
    }

    #[Override]
    public function lock(string $accountId, int $lockedUntil): bool
    {
        $this->ensureRow($accountId);
        $this->execute(
            'UPDATE {table} SET locked_until = ? WHERE realm = ? AND account_id = ?',
            [$lockedUntil, $this->realm, $accountId],
        );

        return true;
    }

    #[Override]
    public function recordFailure(string $accountId): int
    {
        $this->ensureRow($accountId);
        $this->execute(
            'UPDATE {table} SET failed_attempts = failed_attempts + 1 WHERE realm = ? AND account_id = ?',
            [$this->realm, $accountId],
        );

        return $this->fetch($accountId)->failedAttempts;
    }

    #[Override]
    public function recordSuccess(string $accountId, int $loginAt): bool
    {
        $this->ensureRow($accountId);
        $this->execute(
            'UPDATE {table} SET failed_attempts = 0, locked_until = NULL, last_login_at = ?'
            . ' WHERE realm = ? AND account_id = ?',
            [$loginAt, $this->realm, $accountId],
        );

        return true;
    }

    private function ensureRow(string $accountId): bool
    {
        // The column is VARCHAR(64): a longer id could be truncated into another account's id.
        if ($accountId === '' || strlen($accountId) > 64) {
            throw new InvalidArgumentException('The account id must be 1 to 64 characters long.');
        }

        try {
            $this->execute('INSERT INTO {table} (realm, account_id) VALUES (?, ?)', [$this->realm, $accountId]);
        } catch (PDOException $exception) {
            // SQLSTATE 23000, integrity constraint violation (MySQL and SQLite alike): the row exists already.
            if ($exception->getCode() !== '23000') {
                throw $exception;
            }
        }

        return true;
    }

    /**
     * @param list<int|string> $parameters
     */
    private function execute(string $query, array $parameters): PDOStatement
    {
        $statement = $this->pdoContainer->getPDOService()->prepareStatement(
            $this->pdoContainer->getPDO(),
            str_replace('{table}', $this->tableName, $query),
        );
        $statement->execute($parameters);

        return $statement;
    }
}
