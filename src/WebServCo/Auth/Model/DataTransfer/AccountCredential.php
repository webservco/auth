<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use SensitiveParameter;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * Only for checking a password: never return it to the application.
 */
final readonly class AccountCredential implements DataTransferInterface
{
    public function __construct(public string $accountId, #[SensitiveParameter] public string $passwordHash,)
    {
    }
}
