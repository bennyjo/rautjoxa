# Security policy

Rautjoxa encrypts people's photos and videos and stores them for a lifetime, so security problems matter more here than in most projects.
Thank you for reporting them responsibly.

## Report a vulnerability

Report vulnerabilities privately through GitHub:

1. Open the repository's [**Security** tab](https://github.com/bennyjo/rautjoxa/security).
1. Click **Report a vulnerability**.
1. Describe the problem, the affected code or format rule, and how to reproduce it.

If the **Report a vulnerability** button is missing, contact the maintainer privately through the contact details on [@bennyjo](https://github.com/bennyjo)'s GitHub profile.
Don't open a public issue, pull request, or discussion for a vulnerability.

The maintainer aims to acknowledge a report within 14 days, then agrees a fix and a disclosure date with you.
If you want, the advisory credits you for the report.

## Supported versions

Rautjoxa has no releases yet.
Security fixes go to the `main` branch.

Packs are stored under write-once retention and can never be rewritten, so a flaw in the [pack format](docs/format.md) can't be fixed in packs that already exist.
Reports about the format are especially welcome before the app stores real data.

## Scope

In scope:

- The archive core in [`core/`](core), including the pack writer and reader.
- The pack format specification in [`docs/format.md`](docs/format.md).
- The CI workflows in [`.github/workflows/`](.github/workflows).

The keys in [`core/pack/testdata/v1`](core/pack/testdata/v1) are public test keys by design.
They protect only the test vectors, so publishing them is not a vulnerability.
