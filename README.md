# webservco/auth

A PHP component/library. Please see [webservco/sandbox](https://webservco.github.io/sandbox/) for an example project using these types of components.

Password authentication and authenticated sessions for any account table, with throttling, legacy password upgrade, session timeouts and an optional second factor.

- Requires: the `auth_account_state` table in [`resources/auth.sql`](resources/auth.sql); a started session from `webservco/session`
- Related: `webservco/mfa` (TOTP second factor, through the adapter below); `webservco/database` (the PDO container)

---

## Installation

```shell
composer require webservco/auth
```

---

## Usage

One realm per kind of account (`admin`, `customer`…). The account table is the application's own: auth reads it through a mapping and only updates the password column when it upgrades a hash.

```php
use WebServCo\Auth\Factory\AccountStorageFactory;
use WebServCo\Auth\Factory\AuthenticationServiceFactory;
use WebServCo\Auth\Factory\LoginServiceFactory;
use WebServCo\Auth\Model\DataTransfer\AccountTableConfiguration;
use WebServCo\Auth\Model\DataTransfer\RealmConfiguration;
use WebServCo\Auth\Model\LoginStatus;
use WebServCo\Data\Factory\Extraction\DataExtractionContainerFactory;

$dataExtractionContainer = (new DataExtractionContainerFactory())->createDataExtractionContainer(false);
// $pdoContainer: \WebServCo\Database\Contract\PDOContainerInterface
$accountStorageFactory = new AccountStorageFactory($dataExtractionContainer, $pdoContainer);
// $sessionService: \WebServCo\Session\Contract\SessionServiceInterface, already started
$authenticationServiceFactory = new AuthenticationServiceFactory($accountStorageFactory, $dataExtractionContainer, $sessionService);
$loginServiceFactory = new LoginServiceFactory($accountStorageFactory, $authenticationServiceFactory);

// Timeouts in seconds: 1800 idle, 43200 in all, 300 for a pending login.
$realm = new RealmConfiguration('customer');
// Table, id, login and password columns; only rows with status = 'active' log in; `name` comes back with the account.
$accountTable = new AccountTableConfiguration('customer', 'id', 'email', 'password_hash', 'status', 'active', ['name']);

// \WebServCo\Auth\Contract\LoginServiceInterface
$loginService = $loginServiceFactory->createLoginService($realm, $accountTable);
// \WebServCo\Auth\Contract\AuthenticationServiceInterface
$authenticationService = $authenticationServiceFactory->createAuthenticationService($realm, $accountTable);

// Login form.
$result = $loginService->login($submittedLogin, $submittedPassword);
// $result->status: LoginStatus::LoggedIn, InvalidCredentials, or Throttled (wait $result->retryAfterSeconds).

// Every protected request: null means "not logged in" (also after a timeout or "log out everywhere").
$account = $authenticationService->getAuthenticatedAccount(); // ?Account: id, login, attributes
$authenticationService->logout();
$authenticationService->logoutEverywhere($account->id); // after a password change or an MFA reset
```

### Second factor with webservco/mfa

auth doesn't depend on mfa. The application plugs it in with a small adapter:

```php
use WebServCo\Auth\Contract\SecondFactorInterface;
use WebServCo\Auth\Model\SecondFactorResult;
use WebServCo\Mfa\Contract\MfaServiceInterface;
use WebServCo\Mfa\Model\VerificationResult;

final readonly class TotpSecondFactor implements SecondFactorInterface
{
    public function __construct(private MfaServiceInterface $mfaService)
    {
    }

    public function getId(): string
    {
        return 'totp';
    }

    public function isEnabled(string $accountId): bool
    {
        return $this->mfaService->getStatus($accountId)->isEnabled;
    }

    public function startChallenge(string $accountId, string $attemptId): string
    {
        return ''; // Nothing to prepare: the code is in the user's app.
    }

    public function verify(string $accountId, string $attemptId, string $response): SecondFactorResult
    {
        return match ($this->mfaService->verify($accountId, $response)) {
            VerificationResult::Accepted, VerificationResult::AcceptedRecoveryCode => SecondFactorResult::Accepted,
            VerificationResult::Locked => SecondFactorResult::Locked,
            VerificationResult::Rejected => SecondFactorResult::Rejected,
        };
    }
}
```

```php
use WebServCo\Auth\Model\SecondFactorPolicy;

// Required: every account needs a second factor. Optional: only accounts with MFA enabled are asked.
$loginService = $loginServiceFactory->createLoginService(
    $realm,
    $accountTable,
    SecondFactorPolicy::Required,
    [new TotpSecondFactor($mfaService)],
);

$result = $loginService->login($submittedLogin, $submittedPassword);
// LoginStatus::SecondFactorRequired: ask for a code (methods: $loginService->getSecondFactorMethods()).
$result = $loginService->completeSecondFactor('totp', $submittedCode); // LoggedIn, SecondFactorRejected or Locked
// LoginStatus::SecondFactorSetupRequired: enroll the pending account with webservco/mfa
// ($authenticationService->getPendingAuthentication()->accountId), then:
$result = $loginService->completeSecondFactorSetup('totp');
```

### New passwords

Check a password when it is set or changed (not at login), then hash it:

```php
use WebServCo\Auth\Service\PasswordHashService;
use WebServCo\Auth\Service\PasswordPolicyService;
use WebServCo\Auth\Service\PwnedPasswordsChecker;

// 8 characters where a second factor is required, 15 where the password is the only factor. Every character is
// allowed and no mix of types is required (NIST SP 800-63B-4).
// \WebServCo\Auth\Contract\PasswordPolicyServiceInterface
$passwordPolicyService = new PasswordPolicyService(
    8,
    // Optional: Have I Been Pwned's free range API. Only 5 characters of the password's SHA-1 are sent.
    new PwnedPasswordsChecker($httpClient, $requestFactory), // a PSR-18 client and a PSR-17 request factory
);
// list of PasswordProblem: TooShort, TooLong (over 72 bytes), ContainsLogin, Common, Breached
$problems = $passwordPolicyService->check($newPassword, $login);
if ($problems === []) {
    $passwordHash = (new PasswordHashService())->hash($newPassword); // Store it in the password column.
}
```

---

## Contracts

| Interface | Implementation | Purpose |
| --- | --- | --- |
| `Contract\LoginServiceInterface` | `Service\LoginService` | The login: password, second factor, setup. |
| `Contract\AuthenticationServiceInterface` | `Service\AuthenticationService` | Session state: guard, pending login, logout, log out everywhere. |
| `Contract\SecondFactorInterface` | the application's adapter | One second-factor method: `totp` today, others later. |
| `Contract\LegacyPasswordVerifierInterface` | the application's | Old hashes (for example MD5), replaced at the next login. |
| `Contract\PasswordHashServiceInterface` | `Service\PasswordHashService` | `password_hash()` with PHP's default settings. |
| `Contract\PasswordPolicyServiceInterface` | `Service\PasswordPolicyService` | Checks a new password: length, login, common list, breaches. |
| `Contract\BreachedPasswordCheckerInterface` | `Service\PwnedPasswordsChecker` | Have I Been Pwned's range API, through any PSR-18 client. |
| `Contract\LoginServiceFactoryInterface` | `Factory\LoginServiceFactory` | Creates `LoginServiceInterface`; also takes the policy, the factors and a legacy verifier. |
| `Contract\AuthenticationServiceFactoryInterface` | `Factory\AuthenticationServiceFactory` | Creates `AuthenticationServiceInterface`. |

Namespaces are relative to `WebServCo\Auth\`.

---

## Notes

- An unknown login, a wrong password and an inactive account give the same result, in the same time.
- From the 5th failed password in a row the account waits 60 s, doubling up to 15 minutes. It is never locked for good.
- The second factor comes after the password, and auth checks it for the pending account itself.
- Each step gets a new session id. The timeouts are checked on the server at every request.
- The common-password list is SecLists' 10,000 most common passwords (MIT, see `resources/common-passwords.LICENSE`).
- Authorization (roles, who may reset MFA) is the application's job. Never log passwords.

---

## Development

```shell
# Start project.
ddev start
# Install dependencies.
ddev c u
# Run all validations.
ddev c c
# Run unit tests.
ddev c test:dox
```

---

## License

[MIT](LICENSE.md)
