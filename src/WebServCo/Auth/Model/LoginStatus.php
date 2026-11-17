<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model;

enum LoginStatus
{
    // Unknown login, wrong password or inactive account.
    case InvalidCredentials;

    case LoggedIn;

    // The method doesn't exist, or isn't enabled for the pending account.
    case MethodNotAvailable;

    // No pending login, it expired (5 minutes), or it waits for the other kind of step.
    case NoPendingLogin;

    // The password was right; the pending login waits for one of getSecondFactorMethods().
    case SecondFactorRequired;

    case SecondFactorLocked;

    case SecondFactorRejected;

    // The password was right; the account must set up a second factor before the login completes.
    case SecondFactorSetupRequired;

    // Too many failed passwords: wait retryAfterSeconds, even with the right password.
    case Throttled;
}
