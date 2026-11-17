<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\AuthFixture;
use WebServCo\Auth\Model\DataTransfer\Account;
use WebServCo\Auth\Model\DataTransfer\AccountState;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\PendingAuthentication;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\PendingStep;
use WebServCo\Auth\Service\AuthenticationService;
use WebServCo\Auth\Service\Storage\PDOAccountStateStorage;
use WebServCo\Auth\Service\Storage\PDOAccountStorage;

#[CoversClass(AuthenticationService::class)]
#[UsesClass(Account::class)]
#[UsesClass(AccountState::class)]
#[UsesClass(AccountTableConfiguration::class)]
#[UsesClass(PDOAccountStateStorage::class)]
#[UsesClass(PDOAccountStorage::class)]
#[UsesClass(PendingAuthentication::class)]
#[UsesClass(RealmConfiguration::class)]
final class AuthenticationServicePendingTest extends TestCase
{
    public function testAPendingLoginIsNotALogin(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $started = $service->startPendingAuthentication(AuthFixture::ACCOUNT_ID, PendingStep::SecondFactor);

        self::assertSame(1, $fixture->getSessionService()->getRegenerations());
        self::assertNull($service->getAuthenticatedAccount());
        self::assertEquals($started, $service->getPendingAuthentication());
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $started->attemptId);
        self::assertSame(AuthFixture::START_TIME, $started->startedAt);
    }

    public function testCompletingAPendingLoginLogsIn(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->startPendingAuthentication(AuthFixture::ACCOUNT_ID, PendingStep::SecondFactor);

        self::assertTrue($service->completePendingAuthentication());
        self::assertSame(2, $fixture->getSessionService()->getRegenerations());
        self::assertSame('42', $service->getAuthenticatedAccount()?->id);
        self::assertNull($service->getPendingAuthentication());
    }

    public function testAPendingLoginExpiresAfterFiveMinutes(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->startPendingAuthentication(AuthFixture::ACCOUNT_ID, PendingStep::SecondFactor);
        $fixture->advanceClock(299);

        self::assertNotNull($service->getPendingAuthentication());

        $fixture->advanceClock(1);

        self::assertNull($service->getPendingAuthentication());
        self::assertFalse($service->completePendingAuthentication());
    }

    public function testCompletingWithoutAPendingLoginFails(): void
    {
        $fixture = new AuthFixture();

        self::assertFalse($fixture->createAuthenticationService()->completePendingAuthentication());
        self::assertSame(0, $fixture->getSessionService()->getRegenerations());
    }

    public function testAPendingLoginReplacesALogin(): void
    {
        $fixture = new AuthFixture();
        $service = $fixture->createAuthenticationService();
        $service->login(AuthFixture::ACCOUNT_ID);
        $service->startPendingAuthentication(AuthFixture::ACCOUNT_ID, PendingStep::SecondFactor);

        self::assertNull($service->getAuthenticatedAccount());
    }

    public function testEachPendingLoginHasItsOwnAttemptIdAndKeepsItsStep(): void
    {
        $service = (new AuthFixture())->createAuthenticationService();
        $first = $service->startPendingAuthentication(AuthFixture::ACCOUNT_ID, PendingStep::SecondFactor);
        $second = $service->startPendingAuthentication(AuthFixture::ACCOUNT_ID, PendingStep::SecondFactorSetup);

        self::assertNotSame($first->attemptId, $second->attemptId);
        self::assertSame(PendingStep::SecondFactorSetup, $service->getPendingAuthentication()?->step);
    }
}
