<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use SensitiveParameter;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;

/**
 * Only for checking a password: never return it to the application.
 *
 * phpcs: "Signature of method should be placed on a single line" conflicts with "Expected 0 blank lines between
 * attribute and its target, both are on same line": a #[SensitiveParameter] parameter needs a multi-line signature.
 *
 * @phpcs:disable SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature.RequiredSingleLineSignature
 */
final readonly class AccountCredential implements DataTransferInterface
{
    public function __construct(
        public string $accountId,
        #[SensitiveParameter]
        public string $passwordHash,
    ) {
    }
}
