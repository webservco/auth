<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service\Storage;

use InvalidArgumentException;
use Override;
use PDOStatement;
use WebServCo\Auth\Contract\Storage\RememberTokenStorageInterface;
use WebServCo\Auth\Model\DataTransfer\RememberToken;
use WebServCo\Data\Contract\Extraction\DataExtractionContainerInterface;
use WebServCo\Database\Contract\PDOContainerInterface;

use function preg_match;
use function str_replace;
use function strlen;

/**
 * Table: `resources/auth.sql`. The table name replaces `{table}` in the SQL, so it is validated; values are bound.
 */
final readonly class PDORememberTokenStorage implements RememberTokenStorageInterface
{
    public function __construct(
        private DataExtractionContainerInterface $dataExtractionContainer,
        private PDOContainerInterface $pdoContainer,
        private string $realm,
        private string $tableName = 'auth_remember_token',
    ) {
        if (preg_match('/^[A-Za-z0-9_-]{1,32}\z/', $realm) !== 1) {
            throw new InvalidArgumentException('The realm must be 1 to 32 letters, digits, "_" or "-".');
        }

        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}\z/', $tableName) !== 1) {
            throw new InvalidArgumentException('Invalid table name.');
        }
    }

    #[Override]
    public function delete(string $selector): bool
    {
        return $this->execute(
            'DELETE FROM {table} WHERE selector = ? AND realm = ?',
            [$selector, $this->realm],
        )->rowCount() === 1;
    }

    #[Override]
    public function deleteExpired(string $accountId, int $now): bool
    {
        $this->execute(
            'DELETE FROM {table} WHERE realm = ? AND account_id = ? AND expires_at <= ?',
            [$this->realm, $accountId, $now],
        );

        return true;
    }

    #[Override]
    public function fetch(string $selector): ?RememberToken
    {
        $row = $this->pdoContainer->getPDOService()->fetchAssoc(
            $this->execute(
                'SELECT account_id, validator_hash, epoch, expires_at FROM {table} WHERE selector = ? AND realm = ?',
                [$selector, $this->realm],
            ),
        );

        if ($row === []) {
            return null;
        }

        $extraction = $this->dataExtractionContainer->getStrictArrayDataExtractionService();

        return new RememberToken(
            $selector,
            $extraction->getString($row, 'account_id'),
            $extraction->getString($row, 'validator_hash'),
            $extraction->getInt($row, 'epoch'),
            $extraction->getInt($row, 'expires_at'),
        );
    }

    #[Override]
    public function save(RememberToken $rememberToken, int $createdAt): bool
    {
        // The column is VARCHAR(64): a longer id could be truncated into another account's id.
        if ($rememberToken->accountId === '' || strlen($rememberToken->accountId) > 64) {
            throw new InvalidArgumentException('The account id must be 1 to 64 characters long.');
        }

        $this->execute(
            'INSERT INTO {table} (selector, realm, account_id, validator_hash, epoch, expires_at, created_at)'
            . ' VALUES (?, ?, ?, ?, ?, ?, ?)',
            [
                $rememberToken->selector,
                $this->realm,
                $rememberToken->accountId,
                $rememberToken->validatorHash,
                $rememberToken->epoch,
                $rememberToken->expiresAt,
                $createdAt,
            ],
        );

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
