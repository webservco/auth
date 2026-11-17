<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Tests\Unit\Assets\FakeClientException;
use WebServCo\Auth\Service\PwnedPasswordsChecker;

/**
 * SHA-1("password") is 5BAA6 + 1E4C9B93F3F0682250B6CF8331B7EE68FD8. No network: the HTTP client is a stub.
 */
#[CoversClass(PwnedPasswordsChecker::class)]
final class PwnedPasswordsCheckerTest extends TestCase
{
    private const string SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

    public function testOnlyTheFirstFiveHashCharactersAreSent(): void
    {
        $request = self::createStub(RequestInterface::class);
        $request->method('withHeader')->willReturnSelf();
        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->expects($this->once())
            ->method('createRequest')
            ->with('GET', 'https://api.pwnedpasswords.com/range/5BAA6')
            ->willReturn($request);
        $checker = new PwnedPasswordsChecker($this->createClient(200, self::SUFFIX . ":52373976\r\n"), $requestFactory);

        self::assertTrue($checker->isBreached('password'));
    }

    public function testAPaddingLineIsNotABreach(): void
    {
        self::assertFalse($this->createChecker(200, "00000AAAA:3\r\n" . self::SUFFIX . ':0')->isBreached('password'));
    }

    public function testAPasswordMissingFromTheAnswerIsNotBreached(): void
    {
        self::assertFalse($this->createChecker(200, "00000AAAA:3\r\n")->isBreached('password'));
    }

    public function testAnErrorStatusIsNotABreach(): void
    {
        self::assertFalse($this->createChecker(503, self::SUFFIX . ':5')->isBreached('password'));
    }

    public function testAnUnreachableServiceIsNotABreach(): void
    {
        $client = self::createStub(ClientInterface::class);
        $client->method('sendRequest')->willThrowException(new FakeClientException('unreachable'));

        self::assertFalse((new PwnedPasswordsChecker($client, $this->createRequestFactory()))->isBreached('password'));
    }

    private function createChecker(int $status, string $body): PwnedPasswordsChecker
    {
        return new PwnedPasswordsChecker($this->createClient($status, $body), $this->createRequestFactory());
    }

    private function createClient(int $status, string $body): ClientInterface
    {
        $stream = self::createStub(StreamInterface::class);
        $stream->method('__toString')->willReturn($body);
        $response = self::createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($status);
        $response->method('getBody')->willReturn($stream);
        $client = self::createStub(ClientInterface::class);
        $client->method('sendRequest')->willReturn($response);

        return $client;
    }

    private function createRequestFactory(): RequestFactoryInterface
    {
        $request = self::createStub(RequestInterface::class);
        $request->method('withHeader')->willReturnSelf();
        $requestFactory = self::createStub(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')->willReturn($request);

        return $requestFactory;
    }
}
