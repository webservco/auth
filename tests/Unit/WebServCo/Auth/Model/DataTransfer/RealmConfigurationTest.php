<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Model\DataTransfer;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;

#[CoversClass(RealmConfiguration::class)]
final class RealmConfigurationTest extends TestCase
{
    public function testTheDefaultTimeouts(): void
    {
        self::assertEquals(new RealmConfiguration('admin', 1800, 43_200, 300), new RealmConfiguration('admin'));
    }

    public function testAnInvalidNameIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The realm must be 1 to 32 letters, digits, "_" or "-".');

        self::assertSame('', (new RealmConfiguration('admin.customer'))->name);
    }

    public function testANameEndingWithANewlineIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The realm must be 1 to 32 letters, digits, "_" or "-".');

        self::assertSame('', (new RealmConfiguration("admin\n"))->name);
    }

    public function testAnIdleTimeoutLongerThanTheAbsoluteOneIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The idle timeout can not be longer than the absolute timeout.');

        self::assertSame('', (new RealmConfiguration('admin', 7200, 3600))->name);
    }

    public function testATimeoutBelowOneSecondIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Timeouts must be at least 1 second.');

        self::assertSame('', (new RealmConfiguration('admin', 0))->name);
    }
}
