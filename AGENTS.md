# Repository Guidelines

## Project Structure & Module Organization
This repository is a small Go CLI with a `main` package for orchestration plus a `provider` subpackage for certificate source integrations. Entry flow starts in `main.go`, configuration loading and validation live in `config.go`, update orchestration is in `updater.go`, and provider registration lives in `provider.go`. Provider contracts and shared provider types live under `provider/`; Tencent Cloud integration lives under `provider/tencentcloud/`. Certificate parsing, deployment, notification, and time helpers are split across `certificate.go`, `deployer.go`, `notifier.go`, and `time.go`. Tests live beside the code in `*_test.go` files. `config.yaml` is the example runtime configuration.

## Build, Test, and Development Commands
Use standard Go tooling:

- `go run . -config=config.yaml` runs the updater locally with the sample config.
- `go build .` builds the `cert-renewer` binary in the repository root.
- `go test ./...` runs the current unit tests.
- `go test -cover ./...` reports coverage; current baseline is modest, so add tests with behavior changes.
- `gofmt -w *.go provider/*.go provider/tencentcloud/*.go` formats all Go files before review.

## Coding Style & Naming Conventions
Follow idiomatic Go. Keep files `gofmt`-clean, use tabs for indentation, and prefer small focused functions. Exported names use `CamelCase`; unexported helpers use `camelCase`; test functions should read like `TestConfigComplete`. Keep provider names and YAML keys aligned with existing config fields such as `defaultProvider`, `notifyUrl`, `globalPostCommands`, and domain-level `postCommands`. When adding a provider or deployment step, keep log and notification messages explicit about stage, domain, and file paths.

## Testing Guidelines
Place tests next to the implementation with the standard `*_test.go` suffix. Prefer table-driven tests for validation and matching logic, following `TestCoveredByPattern`. Add regression tests for config validation, certificate selection, and deploy command rendering whenever behavior changes. Run `go test ./...` before opening a PR.

## Commit & Pull Request Guidelines
Git history is not available in this workspace, so no repository-specific commit convention could be verified. Use short imperative commit subjects such as `validate duplicate domains` or `add wildcard coverage tests`. PRs should describe the operational impact, note any config changes, and include relevant command output for `go test ./...`. If deployment behavior changes, mention rollback considerations.

## Release Guidelines
Do not create or push git tags, GitHub Releases, or release-triggering refs unless the user explicitly asks to publish a version. Normal code changes may be committed and pushed when requested, but release publication requires a separate clear instruction.

When drafting a release description, extract the key commit messages from the release range and list at most 10 items. End the description with a full changelog comparison line, for example: `Full Changelog: v0.1.6...v0.1.7`.

## Security & Configuration Tips
Do not commit real Tencent Cloud credentials or live webhook URLs. Treat `config.yaml` as a template, and prefer sanitized examples in docs and tests. Be careful when editing certificate paths or command hooks such as `globalPostCommands` and domain-level `postCommands`; these commands execute on the certificate host and can affect live reload behavior.
