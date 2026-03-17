# CLAUDIT-SEC — Claude Security Audit Tool

## Project Overview

CLAUDIT-SEC is a read-only, single-file security audit tool for macOS that inspects Claude Desktop and Claude Code configuration, scheduled tasks, extensions, plugins, skills, permissions, and runtime state. It exists in two implementations:

- **`claude_audit.sh`** — Zsh (~1830 lines, requires `jq`) — designed for MDM/CrowdStrike RTR style deployment

Both produce identical audit data. The shell version is the primary deployment target for managed environments.

## Architecture

Both scripts follow the same structure:

1. **Preflight checks** — OS validation, dependency checks
2. **User context detection** — single user, explicit `--user`, or all-users scan
3. **Session directory discovery** — finds `local-agent-mode-sessions/org/user/` paths
4. **14 data collectors** — each reads specific config files and populates findings
5. **Finding aggregation** — counts by severity (CRITICAL, WARN, INFO, REVIEW)
6. **3 output renderers** — ASCII (ANSI color + Unicode tables), HTML (dark theme), JSON (SIEM-ready)

### Data Collectors

| Collector | Source Files | Key Findings |
|-----------|-------------|-------------|
| Desktop Settings | `claude_desktop_config.json` → preferences | keepAwakeEnabled, menuBar, sidebar |
| Cowork Settings | `cowork_settings.json`, `config.json` | scheduledTasks, webSearch, networkMode |
| MCP Servers | `claude_desktop_config.json` → mcpServers | Server names, commands, env var keys |
| Plugins | `installed_plugins.json`, remote manifest, marketplace cache | installed/remote/cached plugins |
| Connectors | `local_*.json` → remoteMcpServersConfig, `.mcp.json` | web/desktop/not_connected |
| Skills | User skills (6 paths), installed plugin skills (3 paths) — see Key Paths | SKILL.md frontmatter parsing |
| Scheduled Tasks | `scheduled-tasks.json` | Cron expressions with english translation |
| Extensions (DXT) | `extensions-installations.json` | Signature status, dangerous tools |
| Extension Settings | `Claude Extensions Settings/*.json` | Allowed directories |
| Blocklist | `extensions-blocklist.json` | Governance control presence |
| Claude Code Settings | `~/.claude/settings.json` | Permission grants |
| File Permissions | stat() on all config files | Group/world readable/writable |
| Runtime | pgrep, pmset, crontab, LaunchAgents | Running processes, sleep assertions |
| Cookies | `Cookies`, `Cookies-journal` | Presence and permissions |

### Key Paths

```
~/Library/Application Support/Claude/          # Claude Desktop dir
  claude_desktop_config.json                   # Desktop prefs + MCP servers
  config.json                                  # App config (network mode, oauth, allowlists)
  extensions-installations.json                # DXT extensions
  extensions-blocklist.json                    # Extension governance
  Claude Extensions Settings/*.json            # Per-extension settings
  local-agent-mode-sessions/<org>/<user>/      # Session directories
    cowork_settings.json                       # Cowork preferences
    scheduled-tasks.json                       # Scheduled tasks
    cowork_plugins/installed_plugins.json       # Installed plugins
    cowork_plugins/marketplaces/               # Marketplace catalog
    cowork_plugins/cache/                      # Downloaded plugin cache
    remote_cowork_plugins/manifest.json        # Org-deployed plugins
    local_*.json                               # Session files with connector state
~/.claude/settings.json                        # Claude Code settings
~/.claude/skills/<skill>/SKILL.md              # Claude Code user skills (manually uploaded)
~/.claude/plugins/marketplaces/<mp>/           # Claude Code marketplace plugin skills
  plugins/<plugin>/skills/<skill>/SKILL.md
  external_plugins/<plugin>/skills/<skill>/SKILL.md
~/Documents/Claude/Scheduled/<skill>/SKILL.md  # Scheduled task skills

Skill scanning paths (collect_skills):
  User skills (source: "user"):
    ~/Documents/Claude/Scheduled/*/SKILL.md                         # Scheduled tasks
    skills-plugin/<uid>/<oid>/skills/*/SKILL.md                     # Cowork-created skills
    ~/.skills/skills/*/SKILL.md                                     # Alt skills dir
    ~/.claude/skills/*/SKILL.md                                     # Claude Code user skills
    <session>/local_*/.claude/skills/*/SKILL.md                     # Session-local skills

  Installed plugin skills (source: "plugin"):
    <session>/remote_cowork_plugins/*/skills/*/SKILL.md             # Org-deployed plugins
    <session>/cowork_plugins/cache/<mp>/<plugin>/<ver>/skills/*/    # Cached (installed) plugins
    ~/.claude/plugins/marketplaces/<mp>/{plugins,external_plugins}/ # Claude Code marketplace

  NOT scanned (marketplace catalog, not installed):
    <session>/cowork_plugins/marketplaces/                          # Full Cowork catalog
```

## Shell Script (`claude_audit.sh`)

### Zsh Compatibility

The shell script uses `#!/bin/zsh` for stock macOS compatibility (Apple ships bash 3.2 which lacks associative arrays). Key `setopt` flags:

| Option | Purpose |
|--------|---------|
| `KSH_ARRAYS` | 0-based array indexing (bash-compatible) |
| `BASH_REMATCH` | `=~` populates `BASH_REMATCH` array |
| `TYPESET_SILENT` | Prevents `local` re-declaration from printing values in loops |
| `NULL_GLOB` | Unmatched globs expand to nothing (prevents NOMATCH errors) |
| `PIPE_FAIL` | Pipeline returns rightmost non-zero exit code |

### Zsh-Specific Gotchas

**Do NOT use these variable names as locals** — they are zsh special variables:
- `path` (tied to `PATH`) — use `_path` instead
- `status` (tied to `$?`) — use `perm_status` or similar
- `fpath` (function autoload path) — avoid entirely
- `match`, `MATCH`, `MBEGIN`, `MEND` — regex related

**Associative array key iteration**: Use `${(k)arr[@]}` not `${!arr[@]}`

**Lowercase expansion**: Use `${(L)var}` not `${var,,}`

**Read into array**: Use `read -rA` not `read -ra`

**No `printf -v`**: Use `var=$(printf ...)` instead

### MDM Deployment

When run as root (uid 0) — which is how MDMs like FleetDM, Jamf, Mosyle, and CrowdStrike RTR execute scripts — the script automatically scans all users with Claude data. No flags needed.

- **As root (MDM)**: Auto-discovers users via `dscl`, scans all with Claude directories
- **As user**: Scans current user only
- `--user USERNAME`: Scans specific user
- `--all-users`: Explicit all-users scan (requires sufficient permissions)

### Output Formats

- **Default (ASCII)**: ANSI-colored terminal output with Unicode box-drawing tables
- **`--json`**: Single JSON object (or array for multi-user) for SIEM ingestion. Sensitive fields auto-redacted.
- **`--html [FILE]`**: Standalone dark-themed HTML report. Created with mode `0600`. Auto-named per user if scanning multiple users.
- **`-q/--quiet`**: Suppresses INFO-only sections, shows only WARN/CRITICAL findings

### Security Properties

- **Read-only** — never modifies any audited files
- **No eval** — no dynamic code execution
- **All variables quoted** — no word-splitting or injection vectors
- **OAuth tokens redacted** — `[REDACTED]` in all output formats
- **MCP env vars** — only key names emitted, never values
- **MCP args** — patterns matching `sk-`, `key=`, `token=`, `secret=`, `password=` are redacted
- **HTML output** — created with `umask 077` (mode 0600)
- **Username validation** — `^[a-zA-Z0-9._-]+$` with explicit `.`/`..` rejection

## Python Script (`claude_audit.py`)

- Python 3.8+, stdlib only (zero external dependencies)
- Uses dataclasses for structured report data
- Same 14 collectors and 3 renderers as the shell version
- Additional JSON fields: `app_config`, `cookies`, `runtime`, `risk_score`, `risk_level`, `extension_settings`, `marketplace_available`, `cowork_enabled_plugins`, `cowork_marketplaces`
- Has a `calculate_risk()` function (defined but not called in `run_audit()` — risk scoring is unused)

## CLI Reference

```
Usage: claude_audit.sh [OPTIONS]

Options:
  --html [FILE]    HTML report (auto-named if no FILE given)
  --json           JSON output for SIEM ingestion
  --user USER      Scan specific user
  --all-users      Scan all users with Claude data
  -q, --quiet      Only show WARN/CRITICAL findings
  --version        Print version and exit
  -h, --help       Show usage
```

## Development Guidelines

- **Single-file constraint**: Both scripts must remain self-contained single files with no external dependencies (except `jq` for the shell version)
- **Read-only invariant**: Never write to, modify, or delete any file being audited
- **Parity**: Changes to data collection logic should be reflected in both implementations
- **Findings format**: `severity` (CRITICAL/WARN/INFO/REVIEW/OK), `section`, `message`, `detail`
- **Sensitive data**: Always redact tokens, keys, passwords, secrets in all output formats
- **New collectors**: Add to both scripts, update the collector table above
- **Testing**: Run both `python3 claude_audit.py --json` and `zsh claude_audit.sh --json`, compare finding counts and section coverage
