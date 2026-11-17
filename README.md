# webservco/auth

A PHP component/library. Please see [webservco/sandbox](https://webservco.github.io/sandbox/) for an example project using these types of components.

Password authentication and authenticated sessions for any account table, with throttling, legacy password upgrade, session timeouts, remember-me and an optional second factor.

- Requires: the `auth_account_state` table in [`resources/auth.sql`](resources/auth.sql) (and `auth_remember_token` for remember-me); a started session from `webservco/session`
- Related: `webservco/mfa` (TOTP second factor, through the adapter below); `webservco/database` (the PDO container)

---

## Installation

```shell
composer require webservco/auth
```

---

## Usage

One realm per kind of account (`admin`, `customer`…). The account table is the application's own: auth reads it through a mapping and only updates the password column when it upgrades a hash. The login column should be `UNIQUE` (a login that matches more than one active row is refused), and the password column should take 60 characters or more (`VARCHAR(255)`).

Serve the site over HTTPS only, with the session cookie `Secure`, `HttpOnly` and `SameSite=Lax` (webservco/session's `CookieConfiguration`).

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
// $result->status: LoginStatus::LoggedIn, InvalidCredentials, or Throttled ($result->retryAfterSeconds, for the log).
// Show InvalidCredentials and Throttled with the same message, for example "Wrong login or password, or too many
// attempts: try again in a few minutes". Only existing accounts are throttled, so a different message would tell
// which logins exist.

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

final class TotpSecondFactor implements SecondFactorInterface
{
    /**
     * @var list<string>
     */
    private array $recoveryCodes = [];

    public function __construct(private readonly MfaServiceInterface $mfaService)
    {
    }

    public function confirmSetup(string $accountId, string $attemptId, #[\SensitiveParameter] string $response): SecondFactorResult
    {
        // Enables MFA when the first code is right.
        $recoveryCodes = $this->mfaService->confirmEnrollment($accountId, $response);

        if ($recoveryCodes === null) {
            return SecondFactorResult::Rejected;
        }

        $this->recoveryCodes = $recoveryCodes;

        return SecondFactorResult::Accepted;
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

    /**
     * After a completed setup: show them once.
     *
     * @return list<string>
     */
    public function getRecoveryCodes(): array
    {
        return $this->recoveryCodes;
    }

    public function verify(string $accountId, string $attemptId, #[\SensitiveParameter] string $response): SecondFactorResult
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
$totpSecondFactor = new TotpSecondFactor($mfaService);
$loginService = $loginServiceFactory->createLoginService(
    $realm,
    $accountTable,
    SecondFactorPolicy::Required,
    [$totpSecondFactor],
);

$result = $loginService->login($submittedLogin, $submittedPassword);

// LoginStatus::SecondFactorRequired: ask for a code (methods: $loginService->getSecondFactorMethods()).
$result = $loginService->completeSecondFactor('totp', $submittedCode);

// LoginStatus::SecondFactorSetupRequired: the setup page shows the QR code for the pending account…
$pendingAccountId = $authenticationService->getPendingAuthentication()?->accountId;
$enrollment = $mfaService->startEnrollment($pendingAccountId, $label);
// …and its form sends the first code from the app. Done here, not on the setup page: the code proves the setup
// belongs to this login.
$result = $loginService->completeSecondFactorSetup('totp', $submittedCode);
// LoggedIn: show $totpSecondFactor->getRecoveryCodes() once.

// Both steps: LoggedIn; SecondFactorRejected (ask again); SecondFactorLocked (too many wrong codes, wait);
// MethodNotAvailable (unknown method, or not set up for the account); NoPendingLogin (expired: log in again).
```

With `SecondFactorPolicy::Required`, an account without a second factor is set up by whoever logs in first with its password. Switch a realm to Required (or reset someone's MFA) only for passwords you trust.

### Old password hashes

Hashes that `password_verify()` doesn't know (MD5, SHA-1…) need a verifier from the application. After the next successful login the password column holds a bcrypt hash instead, so it must take 60 characters (`VARCHAR(255)` leaves room for later algorithms). Without a verifier, accounts with such hashes can't log in.

```php
use WebServCo\Auth\Contract\LegacyPasswordVerifierInterface;

final readonly class Md5PasswordVerifier implements LegacyPasswordVerifierInterface
{
    public function verify(#[\SensitiveParameter] string $password, string $legacyHash): bool
    {
        // Repeat exactly what the old code did to the password before hashing it (trim, addslashes…).
        return hash_equals($legacyHash, md5($password));
    }
}

$loginService = $loginServiceFactory->createLoginService(
    $realm,
    $accountTable,
    legacyPasswordVerifier: new Md5PasswordVerifier(),
);
```

### Remember me

For customer realms, not admin ones: a remembered login outlives the session timeouts, and it doesn't ask for the second factor again (that was done at the login).

```php
use WebServCo\Auth\Model\DataTransfer\RememberMeConfiguration;
use WebServCo\Auth\Model\RememberLogin;
use WebServCo\Session\Model\DataTransfer\CookieConfiguration;

$rememberMe = new RememberMeConfiguration(
    '__Host-remember', // "__Host-": this host only, HTTPS only
    new CookieConfiguration(2_592_000, '/', '', true, true, 'Lax'), // 30 days, path, domain, Secure, HttpOnly, SameSite
);
// The same configuration for both services of the realm.
$authenticationService = $authenticationServiceFactory->createAuthenticationService($realm, $accountTable, $rememberMe);
$loginService = $loginServiceFactory->createLoginService($realm, $accountTable, rememberMeConfiguration: $rememberMe);

// Login form with a "Remember me" checkbox.
$rememberLogin = $rememberChecked ? RememberLogin::Yes : RememberLogin::No;
$result = $loginService->login($submittedLogin, $submittedPassword, $rememberLogin);
```

The cookie is set when the login completes (after the second factor, if any). `getAuthenticatedAccount()` uses it when the session has no valid login, `logout()` deletes it, and `logoutEverywhere()` ends every cookie of the account. A token lasts its lifetime from the login; the database keeps only its SHA-256.

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
// list of PasswordProblem: TooShort, TooLong (over 72 bytes), ContainsLogin, InvalidCharacter (a NUL byte), Common,
// Breached
$problems = $passwordPolicyService->check($newPassword, $login);
if ($problems === []) {
    $passwordHash = (new PasswordHashService())->hash($newPassword); // Store it in the password column.
}
```

### CSRF tokens

Every form that changes something, the login form included, carries the session's token:

```php
use WebServCo\Auth\Service\CsrfTokenService;

// \WebServCo\Auth\Contract\CsrfTokenServiceInterface
$csrfTokenService = new CsrfTokenService($sessionService);
// In the form:
printf('<input type="hidden" name="csrf" value="%s">', $csrfTokenService->getToken());
// On submit, before anything else; answer 403 when it fails:
$isValid = $csrfTokenService->isValidToken($submittedToken);
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
| `Contract\CsrfTokenServiceInterface` | `Service\CsrfTokenService` | One CSRF token per session for forms. |
| `Contract\RememberMeServiceInterface` | `Service\RememberMeService` | The remember-me cookie, used by `AuthenticationService`. |
| `Contract\LoginServiceFactoryInterface` | `Factory\LoginServiceFactory` | Creates `LoginServiceInterface`; also takes the policy, the factors, a legacy verifier and remember-me. |
| `Contract\AuthenticationServiceFactoryInterface` | `Factory\AuthenticationServiceFactory` | Creates `AuthenticationServiceInterface`, with or without remember-me. |

Namespaces are relative to `WebServCo\Auth\`.

---

## Notes

- An unknown login, a wrong password and an inactive account give the same result, in the same time. The same time holds while the stored bcrypt hashes have `PasswordHashService`'s cost (PHP 8.4's default, 12); older hashes get it at their next login.
- From the 5th failed password in a row the account waits 60 s, doubling up to 15 minutes. It is never locked for good. Attempts are counted before the password check, so parallel requests don't get extra guesses.
- The second factor comes after the password, and auth checks it for the pending account itself.
- Each step gets a new session id and a new CSRF token. The timeouts are checked on the server at every request.
- After `logoutEverywhere()`, a login whose password was checked before it is refused, even if it completes later.
- To unlock an account by hand, set `failed_attempts = 0, locked_until = NULL` in `auth_account_state`. Never delete the row: that resets the epoch to 0 and brings back sessions and remember-me tokens that "log out everywhere" ended.
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
