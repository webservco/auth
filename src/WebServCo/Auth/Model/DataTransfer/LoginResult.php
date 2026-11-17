<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model\DataTransfer;

use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Data\Contract\Transfer\DataTransferInterface;

final readonly class LoginResult implements DataTransferInterface
{
    public function __construct(public LoginStatus $status, public int $retryAfterSeconds = 0,)
    {
    }
}
