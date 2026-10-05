# Methodology

## Scope

Coverage counts enabled `user`, `admin`, and `guest` accounts in each snapshot. Service accounts and disabled accounts are excluded, because they do not perform interactive MFA.

## Measures

For each snapshot the tool calculates MFA coverage (any registered method), phishing-resistant coverage, and the same two measures for administrators. Department results use the latest snapshot and show the change in coverage since the first snapshot.

## Findings

| Check | Finding | Severity | NIST SP 800-53 |
|---|---|---|---|
| MFA-01 | Administrator without MFA | Critical | IA-2(1) |
| MFA-02 | User without MFA (recent) | High | IA-2(2) |
| MFA-03 | User without MFA for 3 or more consecutive snapshots | High | IA-2(2) |
| MFA-04 | MFA removed or weakened since the previous snapshot | High | IA-2, IA-5 |
| MFA-05 | Administrator without phishing-resistant MFA | Medium | IA-2(1) |
| MFA-06 | User relies on SMS or voice | Low | IA-2(2), IA-5 |
| MFA-07 | Successful sign-ins through legacy protocols | High | CM-7, IA-2 |
| MFA-08 | Successful single-factor sign-ins through modern clients | Medium | IA-2 |
| MFA-09 | Coverage target not on track | Medium | PM-6 |
| MFA-10 | Administrator phishing-resistant target not on track | Medium | PM-6 |

Users without MFA are reported once: as persistent (MFA-03) if the gap has lasted the configured number of snapshots, otherwise as recent (MFA-02). A drop in method strength between the last two snapshots (MFA-04) is flagged because unexpected MFA removal is a common step in account takeover and a sign of weak help desk verification.

SMS and voice are treated as weak because codes sent over the phone network can be intercepted or redirected; NIST SP 800-63B treats them as restricted authenticators. Legacy protocols such as IMAP, POP3, and basic-authentication SMTP cannot perform MFA, so any successful sign-in through them bypasses MFA regardless of what the user has registered. Failed legacy sign-ins are counted separately because repeated failures there are a common sign of password spraying.

## Projections

Rollouts usually slow as the easy enrollments are finished, so the projection uses a least-squares trend over the three most recent snapshots rather than the average since the start. The tool reports:

- **Achieved** when the latest value meets the target;
- **On track** when the trend reaches the target on or before the target date;
- **Off track** when it reaches the target later, or when coverage is flat or falling;
- **Insufficient data** with fewer than two snapshots.

Projections are estimates that assume the recent pace continues. They are meant to prompt action early, not to predict exact dates.

## Limitations

- Results depend on the accuracy of the exports. Registration reports show methods registered, not methods enforced; enforcement comes from sign-in data.
- The sign-in summary covers only the period and applications exported.
- The tool supports, and does not replace, a formal assessment or the judgment of a qualified auditor.
