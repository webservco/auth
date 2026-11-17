<?php

declare(strict_types=1);

namespace WebServCo\Auth\Contract;

interface PasswordPolicyServiceInterface
{
    /**
     * The problems of a new password; [] when it can be used. Call it when a password is set or changed, not at
     * login.
     *
     * @return list<\WebServCo\Auth\Model\PasswordProblem>
     */
    public function check(string $password, string $login): array;
}
