# Contributing Guide

We welcome contributions to the `cbc-auth` project!

## Development Environment

The easiest way to get started is by using the Docker Compose setup described in the main [README.md](../README.md).

## Code Style

- Follow the standard Go formatting and style guidelines.
- Use `gofmt` to format your code.

## Commit Messages

We use the [Conventional Commits](https://www.conventionalcommits.org/) specification. This helps in automating changelog generation and keeping the commit history clean.

**Format:**

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Example:**

```
feat(auth): add support for ES256 JWT signing
```

## Branching Strategy

- `main`: The stable release branch.
- `develop`: The main development branch.
- `feature/*`: For new features.
- `hotfix/*`: For urgent bug fixes.

## Pull Request Process

1.  Fork the repository.
2.  Create a new branch from `develop`.
3.  Make your changes and add tests.
4.  Ensure your code is well-formatted and all tests pass.
5.  Create a pull request against the `develop` branch.

<!--Personal.AI order the ending-->