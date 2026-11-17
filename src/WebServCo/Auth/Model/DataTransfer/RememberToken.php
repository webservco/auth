<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * A stored remember-me token. The cookie holds "selector:validator"; only the validator's SHA-256 is stored, so a
 * database copy can't be turned into cookies. The epoch is the account's at creation ("log out everywhere" ends it).
 */
final readonly class RememberToken implements DataTransferInterface
{
    public function __construct(
        public string $selector,
        public string $accountId,
        public string $validatorHash,
        public int $epoch,
        public int $expiresAt,
    ) {
    }
}
