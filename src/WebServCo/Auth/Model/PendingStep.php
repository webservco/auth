<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model;

/**
 * What a pending login still needs after the password.
 */
enum PendingStep
{
    // The account has a second factor: it must pass one.
    case SecondFactor;

    // The realm requires a second factor and the account has none yet: it must set one up.
    case SecondFactorSetup;
}
