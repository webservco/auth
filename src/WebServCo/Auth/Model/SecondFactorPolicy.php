<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model;

enum SecondFactorPolicy
{
    // Accounts with a method enabled must use it; the others log in with the password alone.
    case Optional;

    // Every account must pass a second factor; an account without one must set one up first.
    case Required;
}
