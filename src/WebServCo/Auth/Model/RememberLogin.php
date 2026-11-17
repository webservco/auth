<?php

declare(strict_types=1);

namespace WebServCo\Auth\Model;

enum RememberLogin
{
    case No;

    // Keep the login after the browser closes. Ignored where the realm has no remember-me configuration.
    case Yes;
}
