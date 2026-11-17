<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model;

enum PasswordProblem
{
    // Found in a breach by the breached-password checker (only asked when no other problem was found).
    case Breached;

    // One of the most common passwords (bundled list, case-insensitive).
    case Common;

    case ContainsLogin;

    // A NUL byte: bcrypt can't hash it.
    case InvalidCharacter;

    // Over 72 bytes: bcrypt would ignore the rest.
    case TooLong;

    case TooShort;
}
