# Contributing to CLAUDIT

Thanks for your interest in contributing. This guide covers how to submit changes.

## Scope

CLAUDIT is a **read-only audit tool** for Claude Desktop and Claude Code on macOS. Contributions should stay within this scope:

- New data collectors for Claude configuration files
- Improvements to existing collectors (accuracy, coverage)
- Output format fixes (ASCII, HTML, JSON)
- Bug fixes and compatibility improvements
- Documentation improvements

Out of scope:

- Write/modify operations on audited files
- Features requiring dependencies beyond `jq`
- Non-macOS platform support
- Expanding Claude Code coverage beyond `settings.json`

## Development Setup

1. Clone the repo and create a branch from `main`
2. Ensure you have `zsh` and `jq` installed
3. Test your changes: `zsh claude_audit.sh --json | jq .`

## Single-File Constraint

The script must remain a single self-contained file (`claude_audit.sh`) with no external dependencies other than `jq`. Do not split it into modules or add helper scripts.

## Making Changes

1. **Read first** — understand existing code before modifying it
2. **Preserve read-only invariant** — never write to, modify, or delete any audited file
3. **Redact sensitive data** — tokens, keys, passwords, secrets must be `[REDACTED]` in all output formats
4. **Follow the findings format** — `severity` (CRITICAL/WARN/INFO/REVIEW/OK), `section`, `message`, `detail`
5. **Test all three output formats** — terminal, `--html`, and `--json`

## Zsh Compatibility

The script uses `#!/bin/zsh` for stock macOS compatibility. See `CLAUDE.md` for zsh-specific gotchas (special variable names, array syntax, etc.).

## Submitting a Pull Request

1. Fork the repo and create a feature branch
2. Make your changes with clear, focused commits
3. Test on macOS with both `zsh 5.8+` and `jq 1.6+`
4. Open a PR against `main` with a description of what changed and why

## Reporting Security Issues

Use [GitHub's private vulnerability reporting](https://github.com/HarmonicSecurity/claudit-sec/security/advisories/new). Do not open public issues for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
