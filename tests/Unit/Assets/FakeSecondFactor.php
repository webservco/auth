<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Override;
use WebServCo\Auth\Contract\SecondFactorInterface;
use WebServCo\Auth\Model\SecondFactorResult;

use function in_array;

/**
 * Accepts "123456". Records each call with the account id and attempt id it received.
 */
final class FakeSecondFactor implements SecondFactorInterface
{
    /**
     * @var list<string>
     */
    private array $calls = [];

    /**
     * @param list<string> $enabledAccountIds
     */
    public function __construct(
        private string $methodId,
        private array $enabledAccountIds,
        private SecondFactorResult $resultForAWrongAnswer = SecondFactorResult::Rejected,
    ) {
    }

    public function enable(string $accountId): void
    {
        $this->enabledAccountIds[] = $accountId;
    }

    /**
     * @return list<string>
     */
    public function getCalls(): array
    {
        return $this->calls;
    }

    #[Override]
    public function getId(): string
    {
        return $this->methodId;
    }

    #[Override]
    public function isEnabled(string $accountId): bool
    {
        return in_array($accountId, $this->enabledAccountIds, true);
    }

    #[Override]
    public function startChallenge(string $accountId, string $attemptId): string
    {
        $this->calls[] = 'challenge ' . $accountId . ' ' . $attemptId;

        return 'challenge:' . $attemptId;
    }

    #[Override]
    public function verify(string $accountId, string $attemptId, string $response): SecondFactorResult
    {
        $this->calls[] = 'verify ' . $accountId . ' ' . $attemptId;

        if ($response === '123456') {
            return SecondFactorResult::Accepted;
        }

        return $this->resultForAWrongAnswer;
    }
}
