<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use WebServCo\Data\Contract\Transfer\DataTransferInterface;

final readonly class Account implements DataTransferInterface
{
    /**
     * @param array<string,scalar|null> $attributes the configured extra columns
     */
    public function __construct(public string $id, public string $login, public array $attributes,)
    {
    }
}
