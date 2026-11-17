<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Override;
use UnexpectedValueException;
use WebServCo\Session\Contract\CookieServiceInterface;
use WebServCo\Session\Model\DataTransfer\CookieConfiguration;

use function array_key_exists;

/**
 * The browser's cookie jar in memory: what it sends, and what the responses set or remove. It records the
 * configuration of the last change, so the tests can check the cookie attributes.
 */
final class InMemoryCookieService implements CookieServiceInterface
{
    /**
     * @var array<string,string>
     */
    private array $cookies = [];

    private ?CookieConfiguration $lastConfiguration = null;

    private bool $sendsArray = false;

    public function getLastConfiguration(): ?CookieConfiguration
    {
        return $this->lastConfiguration;
    }

    #[Override]
    public function getValue(string $cookieName): ?string
    {
        if ($this->sendsArray) {
            throw new UnexpectedValueException('Cookie value is not scalar.');
        }

        return $this->cookies[$cookieName] ?? null;
    }

    #[Override]
    public function removeCookie(CookieConfiguration $configuration, string $name): bool
    {
        if (!array_key_exists($name, $this->cookies)) {
            return false;
        }

        unset($this->cookies[$name]);
        $this->lastConfiguration = $configuration;

        return true;
    }

    /**
     * The browser sends this cookie, for example an old or forged one.
     */
    public function send(string $name, string $value): void
    {
        $this->cookies[$name] = $value;
    }

    /**
     * The browser sends "name[]=…", which PHP reads as an array.
     */
    public function sendArray(): void
    {
        $this->sendsArray = true;
    }

    #[Override]
    public function set(CookieConfiguration $configuration, string $name, string $value): bool
    {
        $this->cookies[$name] = $value;
        $this->lastConfiguration = $configuration;

        return true;
    }
}
