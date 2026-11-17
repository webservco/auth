<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Override;
use WebServCo\Auth\Contract\BreachedPasswordCheckerInterface;

use function in_array;

/**
 * Knows a fixed list of breached passwords and records what it was asked.
 */
final class FakeBreachedPasswordChecker implements BreachedPasswordCheckerInterface
{
    /**
     * @var list<string>
     */
    private array $checkedPasswords = [];

    /**
     * @param list<string> $breachedPasswords
     */
    public function __construct(private array $breachedPasswords,)
    {
    }

    /**
     * @return list<string>
     */
    public function getCheckedPasswords(): array
    {
        return $this->checkedPasswords;
    }

    #[Override]
    public function isBreached(string $password): bool
    {
        $this->checkedPasswords[] = $password;

        return in_array($password, $this->breachedPasswords, true);
    }
}
