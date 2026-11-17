<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Override;
use PDO;
use WebServCo\Database\Contract\PDOContainerInterface;
use WebServCo\Database\Contract\PDOServiceInterface;
use WebServCo\Database\Service\PDOService;

/**
 * In-memory SQLite with `auth_account_state` (`resources/auth.sql` in SQLite syntax) and an application account
 * table shaped like the legacy admin's: integer id, username, password hash, status 'on'/'off', role.
 * PDO is set up like webservco/database's PDOFactory: exceptions, associative fetch, no emulated prepares.
 */
final class SqlitePDOContainer implements PDOContainerInterface
{
    private const string SCHEMA = <<<'SQL'
        CREATE TABLE auth_account_state (
            realm TEXT NOT NULL,
            account_id TEXT NOT NULL,
            epoch INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NULL,
            last_login_at INTEGER NULL,
            PRIMARY KEY (realm, account_id)
        );
        CREATE TABLE auth_remember_token (
            selector TEXT NOT NULL PRIMARY KEY,
            realm TEXT NOT NULL,
            account_id TEXT NOT NULL,
            validator_hash TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE user_account (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            status TEXT NOT NULL,
            role TEXT NULL
        );
        SQL;

    private ?PDO $pdo = null;

    #[Override]
    public function createPDO(): PDO
    {
        $pdo = new PDO(
            'sqlite::memory:',
            null,
            null,
            [
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ],
        );
        $pdo->exec(self::SCHEMA);

        return $pdo;
    }

    #[Override]
    public function getPDO(): PDO
    {
        return $this->pdo ??= $this->createPDO();
    }

    #[Override]
    public function getPDOService(): PDOServiceInterface
    {
        return new PDOService();
    }

    public function insertUser(int $id, string $username, string $passwordHash, string $status = 'on'): bool
    {
        $statement = $this->getPDOService()->prepareStatement(
            $this->getPDO(),
            'INSERT INTO user_account (id, username, password, status, role) VALUES (?, ?, ?, ?, ?)',
        );

        return $statement->execute([$id, $username, $passwordHash, $status, 'editor']);
    }
}
