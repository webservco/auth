<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use InvalidArgumentException;
use Override;
use SensitiveParameter;
use UnexpectedValueException;
use WebServCo\Auth\Contract\BreachedPasswordCheckerInterface;
use WebServCo\Auth\Contract\PasswordPolicyServiceInterface;
use WebServCo\Auth\Model\PasswordProblem;

use function dirname;
use function file_get_contents;
use function is_readable;
use function preg_match_all;
use function str_contains;
use function strlen;
use function strtolower;

/**
 * NIST SP 800-63B-4: a minimum length, every character allowed (spaces and Unicode too), no rules about mixing
 * character types, and a blocklist of common and breached passwords.
 */
final readonly class PasswordPolicyService implements PasswordPolicyServiceInterface
{
    private const int MAXIMUM_BYTES = 72;

    /**
     * @param int $minimumLength in characters: 8 where a second factor is required, 15 where the password is the
     *     only factor
     * @param ?string $commonPasswordsFile one password per line; null: the bundled `resources/common-passwords.txt`
     */
    public function __construct(
        private int $minimumLength = 15,
        private ?BreachedPasswordCheckerInterface $breachedPasswordChecker = null,
        private ?string $commonPasswordsFile = null,
    ) {
        if ($minimumLength < 8) {
            throw new InvalidArgumentException('The minimum length must be at least 8 characters.');
        }
    }

    #[Override]
    public function check(#[SensitiveParameter] string $password, string $login,): array
    {
        $problems = $this->findLocalProblems($password, $login);

        // The breach check is a network call: only make it for a password that is otherwise fine.
        if ($problems !== [] || $this->breachedPasswordChecker === null) {
            return $problems;
        }

        if ($this->breachedPasswordChecker->isBreached($password)) {
            return [PasswordProblem::Breached];
        }

        return [];
    }

    private function containsLogin(#[SensitiveParameter] string $password, string $login,): bool
    {
        // str_contains() is always true for an empty needle.
        if ($login === '') {
            return false;
        }

        return str_contains(strtolower($password), strtolower($login));
    }

    private function countCharacters(#[SensitiveParameter] string $password,): int
    {
        $count = preg_match_all('/./su', $password);

        // Not valid UTF-8: count bytes.
        if ($count === false) {
            return strlen($password);
        }

        return $count;
    }

    /**
     * @return list<\WebServCo\Auth\Model\PasswordProblem>
     */
    private function findLocalProblems(#[SensitiveParameter] string $password, string $login,): array
    {
        $problems = [];

        if ($this->countCharacters($password) < $this->minimumLength) {
            $problems[] = PasswordProblem::TooShort;
        }

        if (strlen($password) > self::MAXIMUM_BYTES) {
            $problems[] = PasswordProblem::TooLong;
        }

        if ($this->containsLogin($password, $login)) {
            $problems[] = PasswordProblem::ContainsLogin;
        }

        if (str_contains($password, "\0")) {
            $problems[] = PasswordProblem::InvalidCharacter;
        }

        if ($this->isCommon($password)) {
            $problems[] = PasswordProblem::Common;
        }

        return $problems;
    }

    private function isCommon(#[SensitiveParameter] string $password,): bool
    {
        $file = $this->commonPasswordsFile ?? dirname(__DIR__, 4) . '/resources/common-passwords.txt';
        $commonPasswords = is_readable($file)
            ? file_get_contents($file)
            : false;

        if ($commonPasswords === false) {
            throw new UnexpectedValueException('Unable to read the common password list.');
        }

        return str_contains("\n" . strtolower($commonPasswords) . "\n", "\n" . strtolower($password) . "\n");
    }
}
