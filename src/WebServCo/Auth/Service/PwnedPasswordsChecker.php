<?php

declare(strict_types=1);

namespace WebServCo\Auth\Service;

use Override;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use SensitiveParameter;
use WebServCo\Auth\Contract\BreachedPasswordCheckerInterface;

use function explode;
use function sha1;
use function str_starts_with;
use function strlen;
use function strtoupper;
use function substr;
use function trim;

/**
 * Have I Been Pwned's free Pwned Passwords range API, with k-anonymity: only the first 5 characters of the
 * password's SHA-1 are sent. The API returns every known hash with that start (about 2,000) and the match is made
 * here, so neither the password nor its full hash leaves the server. Padding hides the size of the answer.
 */
final readonly class PwnedPasswordsChecker implements BreachedPasswordCheckerInterface
{
    private const string URL = 'https://api.pwnedpasswords.com/range/';

    /**
     * @param \Psr\Http\Client\ClientInterface $httpClient a PSR-18 client (webservco/http-client); set its timeout
     */
    public function __construct(private ClientInterface $httpClient, private RequestFactoryInterface $requestFactory,)
    {
    }

    /**
     * When the API can't be reached the answer is false, and the other checks of the policy still apply.
     */
    #[Override]
    public function isBreached(#[SensitiveParameter] string $password,): bool
    {
        $hash = strtoupper(sha1($password));
        $request = $this->requestFactory->createRequest('GET', self::URL . substr($hash, 0, 5))
            ->withHeader('Add-Padding', 'true')
            ->withHeader('User-Agent', 'webservco-auth');

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface) {
            return false;
        }

        if ($response->getStatusCode() !== 200) {
            return false;
        }

        return $this->containsHashSuffix((string) $response->getBody(), substr($hash, 5));
    }

    /**
     * Each line is "SUFFIX:COUNT"; padding lines have a count of 0.
     */
    private function containsHashSuffix(string $body, string $suffix): bool
    {
        $prefix = $suffix . ':';

        foreach (explode("\n", $body) as $line) {
            if (!str_starts_with($line, $prefix)) {
                continue;
            }

            return (int) substr(trim($line), strlen($prefix)) > 0;
        }

        return false;
    }
}
