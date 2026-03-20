# 🛡️ CLAUDIT-SEC

**Security audit tool for Claude Desktop on macOS — including CoWork, extensions, plugins, MCP servers, connectors, and scheduled tasks.**

One command. Full visibility. Read-only.

<p align="center">
  <img src="media/claudit-terminal.png" alt="CLAUDIT terminal output" width="700">
</p>

## 🤔 Why

Claude Desktop introduces a new class of endpoint risk: AI agents with autonomous execution, persistent scheduled tasks, MCP server integrations, browser-control extensions, and OAuth-authenticated connectors to external services. Most of this configuration lives in JSON files scattered across multiple directories with no centralised visibility.

CLAUDIT gives you that visibility in a single command.

> 📝 **A note on "Code":** Claude Desktop includes a built-in agent coding feature called **Code** (visible in the app's sidebar). This is **not** the same as **Claude Code**, the standalone terminal CLI. CLAUDIT primarily audits Claude Desktop and its CoWork features. It does include a basic check of `~/.claude/settings.json` (the terminal CLI's config), but the focus is squarely on the Desktop app.

## 📋 What It Audits

| Area | What's Checked |
|------|---------------|
| 🖥️ **Desktop Settings** | `keepAwakeEnabled`, sidebar/menuBar preferences |
| 🤖 **CoWork Settings** | Scheduled tasks, web search, browser use, network mode, egress policy, enabled plugins, marketplaces |
| 🔌 **MCP Servers** | Server names, commands, arguments, environment variable keys |
| 🧩 **Extensions (DXT)** | Installed extensions, signature status, dangerous tool grants |
| ⚙️ **Extension Settings** | Per-extension allowed directories and configuration |
| 🚦 **Extension Governance** | Allowlist enabled/disabled, blocklist entries |
| 📦 **Plugins** | Installed, remote (org-deployed), cached (downloaded) |
| 🪝 **Plugin Hooks** | Lifecycle hooks executing shell commands (PreToolUse, PostToolUse, Stop, etc.) |
| 🔗 **Connectors** | OAuth-authenticated web services, desktop integrations |
| 🎯 **Skills** | User-created, scheduled, session-local, and plugin skills across 9 paths |
| ⏰ **Scheduled Tasks** | Task names, cron expressions (with plain English translation) |
| 🔐 **App Config** | Network mode, extension allowlist/blocklist keys, device identifiers |
| 🔇 **Disabled MCP Tools** | Per-session tools explicitly disabled (with dangerous tool callout) |
| 🏃 **Runtime State** | Running processes, sleep assertions, LaunchAgents, crontab entries |
| 🍪 **Cookies** | `Cookies` and `Cookies-journal` presence |

> 📖 For a detailed breakdown of every individual check, what it means, and why it matters, see the [Findings Reference](docs/findings-reference.md).

## ⚡ Getting Started

### Prerequisites

| Requirement | How to check | How to install |
|-------------|-------------|---------------|
| 🍎 **macOS** | You're on a Mac | — |
| 🐚 **zsh** | `zsh --version` | Ships with macOS since Catalina |
| 🔧 **jq** | `jq --version` | `brew install jq` |

### Install & Run

```bash
git clone https://github.com/HarmonicSecurity/claudit-sec.git
cd claudit-sec
chmod +x claude_audit.sh
./claude_audit.sh
```

That's it. The script reads your Claude configuration and prints a colour-coded report to the terminal. It never modifies anything.

## 🎛️ Usage

```
./claude_audit.sh [OPTIONS]

Options:
  --html [FILE]    Generate a standalone HTML report
  --json           Output structured JSON
  --user USER      Audit a specific user
  --all-users      Audit all users with Claude data (requires root)
  -q, --quiet      Only show WARN and CRITICAL findings
  --version        Print version and exit
  -h, --help       Show usage
```

### Examples

```bash
# Default: colour output in terminal
./claude_audit.sh

# Only warnings and critical findings
./claude_audit.sh -q

# Standalone HTML report
./claude_audit.sh --html

# JSON for SIEM ingestion
./claude_audit.sh --json > audit.json

# Specific user
./claude_audit.sh --user jsmith

# All users (run as root via MDM, FleetDM, Jamf, etc.)
sudo ./claude_audit.sh
```

> 💡 When run as **root** (uid 0), the script automatically discovers and scans all users with Claude data. No flags needed.

## 📊 Output Formats

### 🖥️ Terminal (default)

Colour-coded output with Unicode tables and severity indicators.

<p align="center">
  <img src="media/claudit-terminal.png" alt="CLAUDIT terminal output" width="700">
</p>

### 🌐 HTML (`--html`)

Standalone dark-themed report with collapsible sections. Created with restrictive file permissions (`0600`).

<p align="center">
  <img src="media/claudit-html.png" alt="CLAUDIT HTML report" width="700">
</p>

### 📄 JSON (`--json`)

Structured output for SIEM ingestion. Sensitive fields (OAuth tokens, API keys, secrets) are automatically redacted. Multi-user scans produce a JSON array.

## 🚨 Severity Levels

| Severity | Meaning |
|----------|---------|
| 🟠 **WARN** | Increases risk surface — e.g. unsigned extensions, autonomous execution enabled |
| 🟡 **REVIEW** | Needs human judgement — e.g. org-deployed plugins, MCP servers present |
| 🔵 **INFO** | Informational — e.g. Claude is running, permissions granted |

## 📖 Documentation

| Doc | Description |
|-----|-------------|
| [Findings Reference](docs/findings-reference.md) | Every individual check CLAUDIT performs, what it means, why it matters (risk, compliance, AI enablement), and what to do about it |

## 🔒 Security Properties

- **Read-only** — never writes to, modifies, or deletes any audited file
- **No network access** — all data collected from local filesystem and system commands
- **Sensitive data redacted** — tokens, keys, and secrets replaced with `[REDACTED]` in all output formats
- **Minimal privileges** — runs as current user; root only needed for multi-user scans
- **Single file** — no dependencies beyond `jq`
- **Auditable** — the entire tool is one readable shell script

## 💜 Built with Claude Code

This project is built and maintained using [Claude Code](https://docs.anthropic.com/en/docs/claude-code). We love it. Seriously. If you're building developer tools and haven't tried it yet, you're missing out.

## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
