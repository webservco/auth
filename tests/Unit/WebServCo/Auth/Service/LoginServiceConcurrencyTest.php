<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\FakeSecondFactor;
use WebServCo\Auth\Contract\AuthenticationServiceInterface;
use WebServCo\Auth\Contract\CredentialVerificationServiceInterface;
use WebServCo\Auth\Model\DataTransfer\LoginResult;
use WebServCo\Auth\Model\DataTransfer\PendingAuthentication;
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Auth\Model\PendingStep;
use WebServCo\Auth\Model\RememberLogin;
use WebServCo\Auth\Model\SecondFactorPolicy;
use WebServCo\Auth\Service\LoginService;

/**
 * Races that one in-memory session can't produce, simulated with stubs.
 */
#[CoversClass(LoginService::class)]
#[UsesClass(LoginResult::class)]
#[UsesClass(PendingAuthentication::class)]
final class LoginServiceConcurrencyTest extends TestCase
{
    public function testTheLoginFailsWhenThePendingStateEndsDuringTheCheck(): void
    {
        $authenticationService = self::createStub(AuthenticationServiceInterface::class);
        $authenticationService->method('getPendingAuthentication')->willReturn(
            new PendingAuthentication('42', 'attempt', PendingStep::SecondFactor, 1_800_000_000, RememberLogin::No),
        );
        // The pending login expired, or another request completed it, after the code was accepted.
        $authenticationService->method('completePendingAuthentication')->willReturn(false);

        $service = new LoginService(
            $authenticationService,
            self::createStub(CredentialVerificationServiceInterface::class),
            SecondFactorPolicy::Optional,
            [new FakeSecondFactor('totp', ['42'])],
        );

        self::assertSame(LoginStatus::NoPendingLogin, $service->completeSecondFactor('totp', '123456')->status);
    }
}
