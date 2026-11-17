<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model;

enum SecondFactorResult
{
    case Accepted;

    // Too many failures: the method refuses even a right answer for now.
    case Locked;

    case Rejected;
}
