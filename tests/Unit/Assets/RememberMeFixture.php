<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Service\RememberMeService;
use WebServCo\Auth\Service\Storage\PDORememberTokenStorage;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;
use WebServCo\Session\Model\DataTransfer\CookieConfiguration;

/**
 * Remember-me on an AuthFixture's database, clock and cookie jar: the cookie "remember", for 30 days.
 */
final readonly class RememberMeFixture
{
    public function __construct(private AuthFixture $authFixture)
    {
    }

    public function createConfiguration(): RememberMeConfiguration
    {
        return new RememberMeConfiguration(
            AuthFixture::REMEMBER_COOKIE,
            new CookieConfiguration(AuthFixture::REMEMBER_LIFETIME, '/', '', true, true, 'Lax'),
        );
    }

    public function createService(string $realm = 'admin'): RememberMeService
    {
        return new RememberMeService(
            $this->authFixture->createStateStorage($realm),
            $this->authFixture->getClock(),
            $this->authFixture->getCookieService(),
            $this->createConfiguration(),
            $this->createTokenStorage($realm),
        );
    }

    public function createTokenStorage(string $realm = 'admin'): PDORememberTokenStorage
    {
        return new PDORememberTokenStorage(
            (new DataExtractionContainerFactory())->createDataExtractionContainer(false),
            $this->authFixture->getPdoContainer(),
            $realm,
        );
    }
}
