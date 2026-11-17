<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model;

enum AuthenticationAttemptResult
{
    // Unknown login, wrong password and inactive account all give this result.
    case InvalidCredentials;

    case Success;

    // Too many failures: wait, even with the right password. Show the same message as for InvalidCredentials if
    // telling existing accounts apart matters.
    case Throttled;
}
