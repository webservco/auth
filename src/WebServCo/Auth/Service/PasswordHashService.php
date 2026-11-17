<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use Override;
use SensitiveParameter;
use WebServCo\Auth\Contract\PasswordHashServiceInterface;

use function password_get_info;
use function password_hash;
use function password_needs_rehash;
use function password_verify;

use const PASSWORD_DEFAULT;

/**
 * phpcs: "Signature of method should be placed on a single line" conflicts with "Expected 0 blank lines between
 * attribute and its target, both are on same line": a #[SensitiveParameter] parameter needs a multi-line signature.
 *
 * @phpcs:disable SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature.RequiredSingleLineSignature
 */
final readonly class PasswordHashService implements PasswordHashServiceInterface
{
    /**
     * @var array<string,int>
     */
    private array $options;

    /**
     * @param ?int $cost bcrypt cost; null: PHP's default. Each step doubles the time; tests can use 4.
     */
    public function __construct(?int $cost = null)
    {
        $this->options = $cost === null
            ? []
            : ['cost' => $cost];
    }

    #[Override]
    public function hash(
        #[SensitiveParameter]
        string $password,
    ): string {
        return password_hash($password, PASSWORD_DEFAULT, $this->options);
    }

    #[Override]
    public function isPasswordHash(string $hash): bool
    {
        $info = password_get_info($hash);

        // The algorithm is null for anything password_hash() didn't produce.
        return isset($info['algo']);
    }

    #[Override]
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_DEFAULT, $this->options);
    }

    #[Override]
    public function simulateVerification(
        #[SensitiveParameter]
        string $password,
    ): bool {
        /**
         * Psalm: "The call to password_hash is not used". It is called for its time: hashing costs the same as
         * verifying, one bcrypt key setup at the same cost.
         *
         * @psalm-suppress UnusedFunctionCall
         */
        password_hash($password, PASSWORD_DEFAULT, $this->options);

        return false;
    }

    #[Override]
    public function verify(
        #[SensitiveParameter]
        string $password,
        string $hash,
    ): bool {
        return password_verify($password, $hash);
    }
}
