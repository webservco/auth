<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use WebServCo\Auth\Model\AuthenticationAttemptResult;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * The account id is set only on success; the wait is set only when throttled.
 */
final readonly class AuthenticationAttempt implements DataTransferInterface
{
    public function __construct(
        public AuthenticationAttemptResult $result,
        public ?string $accountId,
        public int $retryAfterSeconds,
    ) {
    }
}
