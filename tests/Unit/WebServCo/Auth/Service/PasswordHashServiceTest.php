<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use WebServCo\Auth\Service\PasswordHashService;

use function md5;
use function password_hash;

use const PASSWORD_BCRYPT;

#[CoversClass(PasswordHashService::class)]
final class PasswordHashServiceTest extends TestCase
{
    public function testAHashVerifiesOnlyItsPassword(): void
    {
        $service = new PasswordHashService(4);
        $hash = $service->hash('right password');

        self::assertStringStartsWith('$2y$04$', $hash);
        self::assertTrue($service->verify('right password', $hash));
        self::assertFalse($service->verify('wrong password', $hash));
        self::assertFalse($service->needsRehash($hash));
    }

    public function testOnlyPasswordHashHashesAreRecognized(): void
    {
        $service = new PasswordHashService(4);

        self::assertTrue($service->isPasswordHash($service->hash('right password')));
        self::assertFalse($service->isPasswordHash(md5('right password')));
        self::assertFalse($service->isPasswordHash(''));
    }

    public function testAHashWithOtherSettingsNeedsARehash(): void
    {
        self::assertTrue(
            (new PasswordHashService(4))->needsRehash(password_hash('right password', PASSWORD_BCRYPT, ['cost' => 5])),
        );
    }

    public function testWithoutACostPhpsDefaultIsUsed(): void
    {
        $service = new PasswordHashService();

        self::assertFalse($service->needsRehash($service->hash('right password')));
    }

    public function testSimulateVerificationIsAlwaysFalse(): void
    {
        self::assertFalse((new PasswordHashService(4))->simulateVerification('right password'));
    }
}
