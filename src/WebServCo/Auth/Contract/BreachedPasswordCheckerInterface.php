<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

interface BreachedPasswordCheckerInterface
{
    /**
     * True when the password appears in known breaches. False when it doesn't, or when the check can't be made.
     */
    public function isBreached(string $password): bool;
}
