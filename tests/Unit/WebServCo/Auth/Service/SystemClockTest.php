<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use WebServCo\Auth\Service\SystemClock;

use function time;

#[CoversClass(SystemClock::class)]
final class SystemClockTest extends TestCase
{
    public function testNowIsTheCurrentTime(): void
    {
        $before = time();
        $now = (new SystemClock())->now()->getTimestamp();

        self::assertGreaterThanOrEqual($before, $now);
        self::assertLessThanOrEqual(time(), $now);
    }
}
