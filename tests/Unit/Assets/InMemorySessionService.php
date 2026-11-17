<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Override;
use WebServCo\Session\Contract\SessionServiceInterface;

use function array_key_exists;

/**
 * A started session in memory. The real SessionService starts nothing in the CLI. It records regenerated ids and
 * destruction, so the tests can check them.
 *
 * @phpcs:disable SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint.DisallowedMixedTypeHint
 */
final class InMemorySessionService implements SessionServiceInterface
{
    /**
     * @var array<mixed>
     */
    private array $data = [];

    private bool $destroyed = false;

    private int $regenerations = 0;

    #[Override]
    public function assertStarted(): bool
    {
        return true;
    }

    #[Override]
    public function destroy(): bool
    {
        $this->data = [];
        $this->destroyed = true;

        return true;
    }

    #[Override]
    public function getCookieName(): string
    {
        return 'test_session';
    }

    public function getRegenerations(): int
    {
        return $this->regenerations;
    }

    /**
     * @return array<mixed>
     */
    #[Override]
    public function getSessionData(): array
    {
        return $this->data;
    }

    public function isDestroyed(): bool
    {
        return $this->destroyed;
    }

    #[Override]
    public function isStarted(): bool
    {
        return true;
    }

    #[Override]
    public function regenerateId(): bool
    {
        $this->regenerations += 1;

        return true;
    }

    #[Override]
    public function setSessionDataItem(string $key, mixed $value): bool
    {
        $this->data[$key] = $value;

        return true;
    }

    /**
     * The interface's parameter has no use here: an in-memory session has no storage path.
     *
     * @phan-suppress PhanUnusedPublicFinalMethodParameter
     * @phpcs:disable SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
     */
    #[Override]
    public function start(?string $storagePath = null): bool
    {
        return true;
    }
    // @phpcs:enable

    #[Override]
    public function unsetSessionDataItem(string $key): bool
    {
        if (!array_key_exists($key, $this->data)) {
            return false;
        }

        unset($this->data[$key]);

        return true;
    }
}
