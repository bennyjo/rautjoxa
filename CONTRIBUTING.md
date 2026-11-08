# Contributing to Rautjoxa

Thank you for your interest in Rautjoxa.
This guide explains how to propose a change and what a change needs before it can be merged.

By taking part in this project, you agree to follow the [code of conduct](CODE_OF_CONDUCT.md).

## Report a bug or request a feature

- To report a bug, open an issue with the **Bug report** form.
- To propose a feature or a change to the pack format, open an issue with the **Feature request** form before you write code.
  Rautjoxa is in early development, and agreeing on the approach first saves you work.
- To ask a question, open a blank issue.
- To report a vulnerability, don't open an issue. Follow the [security policy](SECURITY.md).

## Set up a development environment

You need Go at the version that [`core/go.mod`](core/go.mod) names, or later.
To run the stock-tools restore check, you also need the tools listed at the top of [`core/scripts/check-stock-restore.sh`](core/scripts/check-stock-restore.sh).

```sh
git clone https://github.com/bennyjo/rautjoxa.git
cd rautjoxa/core
go test ./...
```

## Make a change

1. Fork the repository and create a branch from `main`.
1. Make your change, with tests that cover it.
1. Run the same checks as CI, from the `core/` directory:

   ```sh
   gofmt -l .
   go vet ./...
   go test -race ./...
   ```

   `gofmt -l .` must print nothing.
1. If you change how packs are written or read, also restore fresh packs with the stock tools.
   Replace `DIR` with an absolute path:

   ```sh
   go test -count=1 ./pack -run TestWriteVectors -vectors-out=DIR
   scripts/check-stock-restore.sh DIR
   ```

1. Update [`docs/format.md`](docs/format.md) and the README when your change affects what they describe.
1. Open a pull request against `main` and fill in the template.

## Pack format rules

Packs are stored under write-once retention and are never rewritten, so changes to the pack format need extra care.
[`docs/format.md`](docs/format.md) specifies the format and the rules for changing it and its test vectors in [`core/pack/testdata/v1`](core/pack/testdata/v1).
Before you change either, open an issue and agree on the change.

## Commit messages

Write commit messages in the [Conventional Commits](https://www.conventionalcommits.org/) style, with a scope where one fits, such as `feat(core): ...`, `fix(core): ...`, or `docs: ...`.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the project's license.
