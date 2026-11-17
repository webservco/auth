<?php

declare(strict_types=1);

namespace Tests\Unit\Assets;

use Psr\Http\Client\ClientExceptionInterface;
use RuntimeException;

final class FakeClientException extends RuntimeException implements ClientExceptionInterface
{
}
