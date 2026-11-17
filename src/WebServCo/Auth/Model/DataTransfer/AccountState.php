<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * Times are Unix seconds. The epoch grows on "log out everywhere"; sessions from an older epoch end.
 */
final readonly class AccountState implements DataTransferInterface
{
    public function __construct(
        public int $failedAttempts,
        public ?int $lockedUntil,
        public int $epoch,
        public ?int $lastLoginAt,
    ) {
    }
}
