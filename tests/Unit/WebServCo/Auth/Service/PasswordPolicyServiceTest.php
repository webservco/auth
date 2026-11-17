<?php

declare(strict_types=1);

namespace Tests\Unit\WebServCo\Auth\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tests\Unit\Assets\FakeBreachedPasswordChecker;
use UnexpectedValueException;
use WebServCo\Auth\Model\PasswordProblem;
use WebServCo\Auth\Service\PasswordPolicyService;

use function str_repeat;

#[CoversClass(PasswordPolicyService::class)]
final class PasswordPolicyServiceTest extends TestCase
{
    public function testALongEnoughUncommonPasswordIsAccepted(): void
    {
        self::assertSame([], (new PasswordPolicyService(8))->check('x7#Lq!pZ', 'editor'));
    }

    public function testTheLengthCountsCharactersNotBytes(): void
    {
        $service = new PasswordPolicyService(8);

        // 8 characters in 16 bytes, then 7 characters.
        self::assertSame([], $service->check('ăîșțăîșț', 'editor'));
        self::assertSame([PasswordProblem::TooShort], $service->check('ăîșțăîș', 'editor'));
    }

    public function testEveryCharacterIsAllowedAndNoMixIsRequired(): void
    {
        self::assertSame([], (new PasswordPolicyService())->check('correct horse battery staple', 'editor'));
        self::assertSame([], (new PasswordPolicyService(8))->check('§±¶•ª º~^`{}|', 'editor'));
    }

    public function testANulByteIsRefused(): void
    {
        self::assertSame(
            [PasswordProblem::InvalidCharacter],
            (new PasswordPolicyService(8))->check("x7#Lq!pZ\0", 'editor'),
        );
    }

    public function testMoreThanSeventyTwoBytesIsTooLong(): void
    {
        self::assertSame(
            [PasswordProblem::TooLong],
            (new PasswordPolicyService())->check(str_repeat('ab3$', 18) . 'x', 'editor'),
        );
    }

    public function testAPasswordContainingTheLoginIsRefused(): void
    {
        self::assertSame(
            [PasswordProblem::ContainsLogin],
            (new PasswordPolicyService())->check('my-EDITOR-password-2026', 'editor'),
        );
    }

    public function testACommonPasswordIsRefusedWhateverItsCase(): void
    {
        self::assertSame([PasswordProblem::Common], (new PasswordPolicyService(8))->check('PASSWORD', 'editor'));
    }

    public function testTheBreachCheckRunsOnlyForAnOtherwiseGoodPassword(): void
    {
        $checker = new FakeBreachedPasswordChecker(['x7#Lq!pZ']);
        $service = new PasswordPolicyService(8, $checker);

        self::assertSame([PasswordProblem::Breached], $service->check('x7#Lq!pZ', 'editor'));
        self::assertSame([PasswordProblem::TooShort], $service->check('z!7', 'editor'));
        self::assertSame(['x7#Lq!pZ'], $checker->getCheckedPasswords());
    }

    public function testAMinimumBelowEightIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The minimum length must be at least 8 characters.');

        self::assertSame([], (new PasswordPolicyService(6))->check('x7#Lq!pZ', 'editor'));
    }

    public function testAMissingListIsReported(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessageIs('Unable to read the common password list.');

        self::assertSame([], (new PasswordPolicyService(8, null, '/missing/list.txt'))->check('x7#Lq!pZ', 'editor'));
    }
}
