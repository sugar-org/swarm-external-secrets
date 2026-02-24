# Contributing to swarm-external-secrets

Thank you for your interest in contributing to **swarm-external-secrets**! 🎉
This project is a Docker Swarm secrets plugin that integrates with HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, OpenBao, and more. We welcome contributions of all kinds — bug fixes, new provider support, documentation improvements, and more.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Fork & Clone](#fork--clone)
  - [Set Up the Development Environment](#set-up-the-development-environment)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
  - [Available Tasks (Makim)](#available-tasks-makim)
  - [Pre-commit Hooks (Lefthook)](#pre-commit-hooks-lefthook)
  - [Building the Plugin](#building-the-plugin)
  - [Running Tests](#running-tests)
  - [Linting](#linting)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Adding a New Provider](#adding-a-new-provider)
- [Documentation](#documentation)
- [Google Summer of Code 2026](#google-summer-of-code-2026)
- [Getting Help](#getting-help)

---

## Code of Conduct

This project follows a standard open-source Code of Conduct. Please be respectful, inclusive, and constructive in all interactions. Harassment or abusive behaviour will not be tolerated.

---

## Getting Started

### Prerequisites

Make sure the following tools are installed on your system:

| Tool | Version | Purpose |
|------|---------|---------|
| [Go](https://go.dev/dl/) | ≥ 1.24 | Primary language |
| [Docker](https://docs.docker.com/get-docker/) | latest | Plugin build & testing |
| [Makim](https://makim.readthedocs.io/) | latest | Task runner |
| [Lefthook](https://github.com/evilmartians/lefthook) | latest | Git hooks manager |
| [golangci-lint](https://golangci-lint.run/usage/install/) | latest | Go linter |
| [gosec](https://github.com/securego/gosec) | latest | Security scanner |
| [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports) | latest | Import formatter |
| [gocyclo](https://github.com/fzipp/gocyclo) | latest | Cyclomatic complexity checker |

Install Go tools with:

```bash
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
```

### Fork & Clone

1. Fork this repository on GitHub.
2. Clone your fork locally:

```bash
git clone https://github.com/<your-username>/swarm-external-secrets.git
cd swarm-external-secrets
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/sugar-org/swarm-external-secrets.git
```

### Set Up the Development Environment

Install Git hooks via the setup script (this configures Lefthook):

```bash
./setup-hooks.sh
```

Install Go module dependencies:

```bash
go mod download
```

---

## Project Structure

```
swarm-external-secrets/
├── main.go            # Plugin entry point
├── driver.go          # Core Docker secrets driver logic
├── utils.go           # Shared utility functions
├── providers/         # Secret provider implementations
│   ├── vault/         # HashiCorp Vault / OpenBao
│   ├── aws/           # AWS Secrets Manager
│   └── azure/         # Azure Key Vault
├── monitoring/        # Health & metrics dashboard
├── scripts/           # Shell scripts for build, test, deploy
├── docs/              # Documentation sources
├── .makim.yaml        # Makim task definitions
├── lefthook.yml       # Git hook definitions
├── Dockerfile         # Plugin Docker image
└── docker-compose.yml # Local development stack
```

---

## Development Workflow

### Available Tasks (Makim)

This project uses [Makim](https://makim.readthedocs.io/) as a task runner. Common tasks are defined in [`.makim.yaml`](.makim.yaml):

| Task | Command | Description |
|------|---------|-------------|
| Build | `makim scripts.build` | Build the plugin image |
| Test | `makim scripts.test` | Run all tests |
| Run | `makim scripts.run` | Start the plugin locally |
| Deploy | `makim scripts.deploy` | Deploy to target environment |
| Cleanup | `makim scripts.cleanup` | Remove containers & build artifacts |
| Health check | `makim scripts.check_plugin_service` | Check plugin service health |
| Demo rotation | `makim scripts.demo_rotation` | Run a secret rotation demo |
| Lint | `makim scripts.linter` | Run all linting tools |
| Full CI | `makim ci.all` | Run the same steps as CI (build → test → health check → cleanup) |

### Pre-commit Hooks (Lefthook)

[Lefthook](https://github.com/evilmartians/lefthook) automatically runs the following checks before each commit:

| Hook | What it does |
|------|-------------|
| `go-tidy` | Runs `go mod tidy` and stages `go.mod`/`go.sum` |
| `go-fmt` | Formats staged `.go` files |
| `go-vet` | Runs `go vet ./...` |
| `go-imports` | Fixes import ordering with `goimports` |
| `golangci-lint` | Full lint suite with a 10-minute timeout |
| `gosec` | Security scan of all Go code |
| `gocyclo` | Fails if cyclomatic complexity exceeds **17** |
| `eof-newline` | Ensures all staged text files end with a POSIX newline |

> **Tip:** To skip hooks in an emergency, use `git commit --no-verify`. Please do not make this a habit.

### Building the Plugin

```bash
makim scripts.build
# or directly:
./scripts/build.sh
```

### Running Tests

```bash
makim scripts.test
# or directly:
./scripts/test.sh
```

### Linting

```bash
makim scripts.linter
# or run golangci-lint directly:
golangci-lint run ./... --timeout 10m
```

---

## Submitting a Pull Request

1. **Keep `main` up to date:**

   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Create a feature branch** with a descriptive name:

   ```bash
   git checkout -b feat/add-gcp-provider
   # or
   git checkout -b fix/vault-rotation-timeout
   ```

3. **Write your code** following the existing code style.

4. **Ensure all checks pass locally:**

   ```bash
   makim ci.all
   ```

5. **Commit your changes.** Write clear, concise commit messages in the imperative mood:
   - ✅ `feat: add GCP Secret Manager provider`
   - ✅ `fix: handle Vault token renewal race condition`
   - ❌ `fixed stuff`

6. **Push your branch** and open a Pull Request against `main`.

7. Fill in the PR template completely — include a description of the change, how it was tested, and any relevant issue numbers.

8. A maintainer will review your PR. Address feedback promptly.

---

## Adding a New Provider

To add support for a new secret backend:

1. Create a new package under `providers/<provider-name>/`.
2. Implement the provider interface expected by `driver.go`.
3. Register the provider in `driver.go` with the appropriate `SECRETS_PROVIDER` value.
4. Add configuration documentation to [`docs/MULTI_PROVIDER.md`](docs/MULTI_PROVIDER.md).
5. Add integration tests in `scripts/test.sh` or a dedicated test script.
6. Update the provider table in [`readme.md`](readme.md).

---

## Documentation

Documentation lives in the [`docs/`](docs/) directory and is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/).

To preview the docs locally:

```bash
pip install mkdocs-material
mkdocs serve
```

When contributing documentation:
- Keep language clear and concise.
- Include working code snippets where possible.
- Update the relevant guide (`MULTI_PROVIDER.md`, `MONITORING.md`, `ROTATION.md`, etc.) when changing behaviour.

---

## Google Summer of Code 2026

**swarm-external-secrets** is participating in [Google Summer of Code 2026](https://summerofcode.withgoogle.com/) under [OpenScienceLabs](http://opensciencelabs.org/).

If you are a student looking to apply, please review the [Project Ideas Wiki](https://github.com/sugar-org/swarm-external-secrets/wiki/Project-Ideas) and start contributing early. Please focus on small implementations or bugfixes and only change the necessary code,"less is more." PRs that are too long or contain unnecessary changes are impossible to review and will be closed.

Feel free to ping us if you need help or use the `#gsoc` channel on [discord](https://discord.gg/GaYjnbtqQ).


---

## Getting Help

- **GitHub Issues** – for bug reports and feature requests.
- **GitHub Discussions** – for questions, ideas, and general conversation.
- **Wiki** – for project ideas and longer-form documentation.

We appreciate every contribution, no matter how small. Thank you for helping make **swarm-external-secrets** better! 🚀
