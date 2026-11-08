# Rautjoxa

A lifelong, durable, low-cost archive for the photos and videos on your phone.

Rautjoxa is a planned Android app for people who want every photo and video they take kept for life, at low cost, without trusting a single company to keep it.
The app will encrypt every original on the phone and store it in two write-once cold archives at two different companies.
The archive is designed so that you can always restore it with the stock `age` and `tar` tools, without the app.

## Status

Rautjoxa is in early development, and there is nothing to install yet.

What exists today:

- The archive core: a Go package that writes and reads encrypted packs.
- Version 1 of the [pack format](docs/format.md), with test vectors that CI restores with the stock `age` and `tar` tools.

What doesn't exist yet: the Android app, the upload to cold storage, and any releases.
Don't use Rautjoxa to protect real data yet.

To see what a pack holds, follow [Restore without Rautjoxa](docs/format.md#restore-without-rautjoxa) with the public test keys and packs in [`core/pack/testdata/v1`](core/pack/testdata/v1).

## Repository layout

- [`core/`](core): the archive core, a Go module. The `pack` package writes and reads encrypted packs.
- [`docs/format.md`](docs/format.md): the pack format specification.

## Development

The core needs Go 1.27 or later:

```sh
cd core
go vet ./...
go test -race ./...
```

## Verify a checkout non-interactively

These steps take a fresh clone to a verified working state, for example in a coding agent's sandbox.
Every command is non-interactive and runs from the repository root in a POSIX shell.
Rautjoxa has no command-line tool yet, so the checks are the Go tests and the stock-tools restore script.

1. Clone the repository:

   ```sh
   git clone https://github.com/bennyjo/rautjoxa.git
   cd rautjoxa
   ```

1. Check the formatting, then vet and test the core.
   You need Go at the version that [`core/go.mod`](core/go.mod) names, or later.

   ```sh
   (cd core && test -z "$(gofmt -l .)" && go vet ./... && go test ./...)
   ```

   Success: the exit status is 0, and `go test` prints a line that starts with `ok` for `github.com/bennyjo/rautjoxa/core/pack`.
   CI also runs the tests with `-race`, which needs cgo and a C compiler.

1. Restore the test vectors with the stock tools.
   You need the tools listed at the top of [`core/scripts/check-stock-restore.sh`](core/scripts/check-stock-restore.sh).
   To install `age` and `age-inspect` with Go, run the following. If `GOBIN` is set, `go install` puts them there instead of `$(go env GOPATH)/bin`.

   ```sh
   go install filippo.io/age/cmd/...@v1.3.2
   export PATH="$(go env GOPATH)/bin:$PATH"
   core/scripts/check-stock-restore.sh core/pack/testdata/v1
   ```

   Success: the exit status is 0, and the script prints a `== <pack> with <key>` line for each check, each followed by an `ok:` line.

### Exit codes and output

| Command | On success | On failure |
|---|---|---|
| `go test ./...` | Exit status 0. | A non-zero exit status, with `FAIL` lines. |
| `go test -json ./...` | Exit status 0. Prints one JSON event per line, and each package ends with an event whose `Action` is `pass`. | A non-zero exit status, and a package ends with an event whose `Action` is `fail`. |
| `core/scripts/check-stock-restore.sh DIR` | Exit status 0, with the output described above. | A failed check prints `FAIL: <reason>` to stderr and exits 1. An error from `age`, `tar`, or `jq` exits with that tool's status, and a missing tool exits 127. |

Go code that uses the `pack` package can test its errors with `errors.Is(err, pack.ErrWrongKey)` and `errors.Is(err, pack.ErrInvalid)`, as [`docs/format.md`](docs/format.md#reader-checks) describes.

## Contributing

Contributions are welcome. Read the [contributing guide](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) first.
To report a vulnerability, follow the [security policy](SECURITY.md) instead of opening an issue.

## License

Copyright 2026 Benny Johansson.

Licensed under the [Apache License 2.0](LICENSE).
