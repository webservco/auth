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
        if (preg_match('/^[A-Za-z0-9_-]{1,32}\z/', $realm) !== 1) {
            throw new InvalidArgumentException('The realm must be 1 to 32 letters, digits, "_" or "-".');
        }

        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}\z/', $tableName) !== 1) {
            throw new InvalidArgumentException('Invalid table name.');
        }
    }

    /**
     * `locked_until` comes first: MySQL evaluates the assignments in order, so it still reads the old count, like
     * SQLite and the SQL standard. The count is compared as a column: PDO binds strings, and SQLite converts a string
     * for a column comparison but not for one with an expression (`failed_attempts + 1`).
     */
    #[Override]
    public function countAttempt(string $accountId, int $now, int $lockFrom, int $lockedUntil): bool
    {
        $this->ensureRow($accountId);

        return $this->execute(
            'UPDATE {table} SET'
            . ' locked_until = CASE WHEN failed_attempts >= ? THEN ? ELSE NULL END,'
            . ' failed_attempts = CASE WHEN failed_attempts < 65535 THEN failed_attempts + 1 ELSE failed_attempts END'
            . ' WHERE realm = ? AND account_id = ? AND (locked_until IS NULL OR locked_until <= ?)',
            [$lockFrom - 1, $lockedUntil, $this->realm, $accountId, $now],
        )->rowCount() === 1;
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
