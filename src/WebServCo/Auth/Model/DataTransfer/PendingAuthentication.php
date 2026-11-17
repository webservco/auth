<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use WebServCo\Auth\Model\PendingStep;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * A login whose password was right but which still needs a step. The attempt id is random and new for each
 * pending login, so a second factor can bind its challenge to this attempt only.
 */
final readonly class PendingAuthentication implements DataTransferInterface
{
    public function __construct(
        public string $accountId,
        public string $attemptId,
        public PendingStep $step,
        public int $startedAt,
    ) {
    }
}
