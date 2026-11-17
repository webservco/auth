<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use InvalidArgumentException;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;

use function preg_match;

/**
 * A realm is one kind of account in one application, such as "admin" or "customer". Timeouts are in seconds:
 * 30 minutes idle, 12 hours in all, 5 minutes for a pending login (NIST SP 800-63B-4 AAL2 allows 1 h and 24 h).
 */
final readonly class RealmConfiguration implements DataTransferInterface
{
    public function __construct(
        public string $name,
        public int $idleTimeout = 1800,
        public int $absoluteTimeout = 43_200,
        public int $pendingTimeout = 300,
    ) {
        if (preg_match('/^[A-Za-z0-9_-]{1,32}\z/', $name) !== 1) {
            throw new InvalidArgumentException('The realm must be 1 to 32 letters, digits, "_" or "-".');
        }

        if ($idleTimeout < 1 || $absoluteTimeout < 1 || $pendingTimeout < 1) {
            throw new InvalidArgumentException('Timeouts must be at least 1 second.');
        }

        if ($idleTimeout > $absoluteTimeout) {
            throw new InvalidArgumentException('The idle timeout can not be longer than the absolute timeout.');
        }
    }
}
