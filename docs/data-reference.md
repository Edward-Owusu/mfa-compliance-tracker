# Data reference

The tool reads two CSV files. Templates are in `samples/`.

## 1. MFA registration snapshots (required)

One row per account per snapshot. Collect a snapshot on a regular schedule, such as the last day of each month, and append it to the same file. Two or more snapshots are needed for trends and projections.

| Column | Values | Notes |
|---|---|---|
| `snapshot_date` | `YYYY-MM-DD` | Date the registration data was exported |
| `username` | text | Must be unique within a snapshot |
| `department` | text | Used for the department comparison (blank becomes "Unassigned") |
| `account_type` | `user`, `admin`, `guest`, `service` | Service accounts are excluded from coverage |
| `enabled` | true/false (blank is treated as enabled) | Disabled accounts are excluded |
| `mfa_method` | see below | The strongest method the account has registered |

Method strength tiers:

| Tier | Methods |
|---|---|
| None | `none` |
| Weak | `sms`, `voice` |
| Standard | `app_push`, `totp`, `hardware_otp` |
| Phishing-resistant | `fido2`, `passkey`, `certificate`, `windows_hello` |

**Where to get it.** Most identity providers offer an MFA registration report that can be downloaded as CSV, for example the user registration details report for authentication methods in the Microsoft Entra admin center, or the equivalent reports in Okta, Duo, or Google Workspace. Download it each month, add a `snapshot_date` column, map each user's strongest registered method to the values above, and add department from your directory or HR system.

## 2. Sign-in summary (optional)

One row per combination of user, application, client, authentication requirement, and result, with a count. This shows where sign-ins succeed without MFA.

| Column | Values |
|---|---|
| `username` | text |
| `application` | text, such as "Exchange Online" |
| `client_app` | the client or protocol, such as `Browser`, `IMAP4`, `POP3`, `Authenticated SMTP`, `Exchange ActiveSync` |
| `auth_requirement` | `single_factor` or `multifactor` |
| `status` | `success` or `failure` (default `success`) |
| `count` | number of sign-ins (default 1) |

Client apps listed in the policy's `legacy_client_apps` are treated as legacy protocols, which cannot perform MFA.

**Where to get it.** Identity provider sign-in logs usually record the client app or protocol and whether single-factor or multifactor authentication was satisfied; in Microsoft Entra ID these appear as the "Client app" and "Authentication requirement" fields. Export a month of sign-ins and summarize them with a spreadsheet pivot table by user, application, client app, authentication requirement, and status.

## Targets and parameters

Defaults are in `src/mfa_tracker/data/policy.json`: 100% coverage and 100% phishing-resistant MFA for administrators by the target date, and three consecutive snapshots before a user counts as a persistent non-enroller. Override any value with a JSON file passed to `--policy`, or adjust targets in the dashboard sidebar.

Sign-in and registration exports identify users and their weaknesses. Store them and the reports securely, and verify report names and fields against your provider's current documentation.
