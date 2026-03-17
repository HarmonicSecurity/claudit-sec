# CLAUDIT

**Claude Desktop & Claude Code Security Audit Tool for macOS**

A read-only, single-file audit script that inventories Claude AI configuration, autonomous capabilities, extensions, plugins, connectors, MCP servers, scheduled tasks, and file permissions across macOS endpoints. Designed for deployment via MDMs (FleetDM, Jamf, Mosyle, Kandji) and CrowdStrike RTR.

## Why This Exists

Claude Desktop and Claude Code introduce a new class of endpoint risk: AI agents with autonomous execution capabilities, persistent scheduled tasks, MCP server integrations, browser control extensions, and OAuth-authenticated connectors to external services. Most of this configuration lives in JSON files across multiple directories with no centralised visibility.

CLAUDIT gives security teams that visibility in a single command.

## What It Audits

| Area | What's Checked | Risk Signal |
|------|---------------|-------------|
| **Desktop Settings** | `keepAwakeEnabled`, sidebar/menuBar preferences | Sleep prevention, persistent background presence |
| **Cowork Settings** | Scheduled tasks toggle, web search toggle, network mode, enabled plugins, extra marketplaces | Autonomous execution, internet access, plugin supply chain |
| **MCP Servers** | Server names, commands, arguments, environment variable keys | Arbitrary command execution surface, credential exposure |
| **Extensions (DXT)** | Installed extensions, signature status, dangerous tool grants | Unsigned code, `write_file`/`execute_javascript`/`run_command` |
| **Extension Settings** | Per-extension allowed directories and configuration | Overly broad filesystem access grants |
| **Extension Governance** | Allowlist enabled/disabled per org, blocklist entries | No allowlist = any extension installable without approval |
| **Plugins** | Installed, remote (org-deployed), cached (downloaded) | Unexpected remote plugins, unvetted marketplace installs |
| **Connectors** | OAuth-authenticated web services, desktop integrations, pending auth | Each connector grants Claude access to an external service |
| **Skills** | User-created, scheduled, session-local, and plugin skills across 9 paths | Custom skills may contain sensitive instructions or targets |
| **Scheduled Tasks** | Task names, cron expressions (with English translation), enabled state | Unreviewed autonomous tasks running on schedules |
| **App Config** | OAuth token presence, network mode, extension allowlist keys | Plaintext credentials, governance controls |
| **Claude Code** | `~/.claude/settings.json` permission grants | Broad tool permissions granted to Claude Code |
| **File Permissions** | `stat()` on all config files, cookies, extension settings | Group/world readable or writable config files |
| **Runtime State** | Running processes, sleep assertions, LaunchAgents, crontab entries, debug dir size | Persistent background execution, sleep prevention |
| **Cookies** | `Cookies` and `Cookies-journal` presence and permissions | Session persistence, permission exposure |

## Audit Findings Reference

This section details every finding CLAUDIT can produce, what triggers it, and why it matters from a security and compliance perspective.

### Desktop Settings

#### `keepAwakeEnabled is ON` (WARN)

**What it detects:** The `preferences.keepAwakeEnabled` flag in `claude_desktop_config.json` is set to `true`.

**Why it matters:** When enabled, Claude Desktop prevents macOS from entering sleep mode by holding a power management assertion. This has several compliance implications:

- **Energy policy violation** — Many organisations enforce sleep/power policies via MDM (e.g. "sleep after 15 minutes of inactivity"). Keep-awake bypasses these controls entirely, potentially violating corporate energy management or sustainability policies.
- **Physical security risk** — Devices that never sleep remain unlocked longer (depending on screensaver settings), increasing the window for physical access attacks in shared or public spaces.
- **Endpoint visibility** — EDR and MDM compliance checks that expect regular sleep/wake cycles may flag the endpoint as non-compliant or miss check-in windows.
- **Battery and hardware** — On laptops, persistent wake drains battery and can cause thermal issues if the lid is closed with sleep prevented.

### Cowork Settings

#### `Scheduled tasks ENABLED` (WARN)

**What it detects:** `preferences.coworkScheduledTasksEnabled` is `true` in `claude_desktop_config.json`.

**Why it matters:** This enables Claude's autonomous task scheduler, allowing it to execute tasks on cron-like schedules without user interaction. Each scheduled task has a SKILL.md file that defines what Claude does when triggered, including which tools it can invoke and what instructions it follows.

- **Shadow IT / autonomous execution** — Scheduled tasks run unattended and can perform actions (send messages, write files, query APIs) without real-time human oversight.
- **Data exfiltration risk** — A scheduled task with web search or connector access could periodically collect and transmit data to external services.
- **Compliance** — Regulated environments (SOX, HIPAA, PCI-DSS) may require that all automated processes are documented and approved. User-created scheduled tasks bypass change management.
- **Persistence** — Scheduled tasks survive application restarts and act as a persistence mechanism for whatever instructions are in the SKILL.md prompt.

#### `Code Desktop scheduled tasks ENABLED` (WARN)

**What it detects:** `preferences.ccdScheduledTasksEnabled` is `true`. This is the Code Desktop variant of the scheduled task toggle.

**Why it matters:** Same risks as the Cowork scheduled tasks toggle above, but for the Code Desktop interface. Both toggles should be reviewed independently as they control different task execution contexts.

#### `Web search ENABLED` (WARN)

**What it detects:** `preferences.coworkWebSearchEnabled` is `true` in `claude_desktop_config.json`.

**Why it matters:** Web search gives Claude the ability to autonomously query the internet during conversations and scheduled tasks.

- **Data leakage via search queries** — Sensitive context from conversations (code snippets, internal project names, customer data) can be embedded in search queries sent to external search providers.
- **Prompt injection via search results** — Web pages returned by search could contain adversarial content designed to manipulate Claude's behaviour (indirect prompt injection).
- **Regulatory exposure** — In regulated industries, allowing an AI agent to autonomously access the internet may violate data handling policies, particularly if conversations involve PII, PHI, or classified material.
- **Network policy bypass** — Web search traffic may bypass proxy or DLP controls depending on how Claude routes requests.

### App Config

#### `Unencrypted OAuth token in plaintext config` (WARN)

**What it detects:** The `config.json` file contains a non-empty `oauth:tokenCache` object.

**Why it matters:** OAuth tokens stored in plaintext on disk can be read by any process running as the user, or by anyone with filesystem access to the home directory.

- **Credential theft** — Malware, a compromised npm package, or a malicious MCP server running in the user's context can read the token and impersonate the user to Anthropic's services.
- **Lateral movement** — If the token grants access to organisational resources (via connectors), a stolen token provides access to those services.
- **Compliance** — Standards like PCI-DSS (Req 3.4), NIST 800-53 (SC-28), and SOC 2 require encryption of credentials at rest. Plaintext token storage is a finding in most compliance audits.
- **Note:** This is currently an Anthropic application default, not a user misconfiguration. CLAUDIT flags it so security teams have visibility.

#### `Extension allowlist DISABLED` (WARN)

**What it detects:** One or more `dxt:allowlistEnabled` keys in `config.json` are set to `false`.

**Why it matters:** The extension allowlist is the primary governance control for DXT extensions. When disabled:

- **No installation gate** — Any user can install any extension from the marketplace or sideload a `.dxt` package without approval.
- **Supply chain risk** — Without an allowlist, there is no vetting step between the marketplace and the endpoint. A malicious or compromised extension could be installed before security teams are aware it exists.
- **Equivalent to unsigned code execution** — Extensions can contain tools like `run_command`, `write_file`, and `execute_javascript`. Without an allowlist, these capabilities are one click away from any user.
- **Recommendation** — Enable the allowlist and maintain an approved set of extensions per organisation. This is the DXT equivalent of application whitelisting.

### Extensions (DXT)

#### `Unsigned extension` (WARN)

**What it detects:** An installed extension has `signatureInfo.status == "unsigned"` in `extensions-installations.json`.

**Why it matters:** Signed extensions have been verified by Anthropic's extension signing process. Unsigned extensions have no such verification.

- **Tampering** — An unsigned extension could have been modified after download (by malware, a supply chain attack, or manual editing). There is no cryptographic proof of integrity.
- **Sideloading** — Unsigned extensions are typically sideloaded (installed from a local `.dxt` file rather than the marketplace). This bypasses any marketplace review process.
- **Trust chain** — In a managed environment, unsigned extensions represent unvetted code running with Claude's tool permissions. This is analogous to running unsigned binaries on endpoints with code-signing enforcement disabled.

#### `Extension has dangerous tools` (WARN)

**What it detects:** An installed extension declares tools from the dangerous set: `execute_javascript`, `write_file`, `edit_file`, `run_command`, `execute_sql`.

**Why it matters:** These tools grant Claude (and by extension, the extension) powerful system-level capabilities:

| Tool | Capability | Risk |
|------|-----------|------|
| `run_command` | Execute arbitrary shell commands | Full system access at user privilege level |
| `write_file` | Create or overwrite any user-accessible file | Data destruction, config tampering, persistence |
| `edit_file` | Modify any user-accessible file | Subtle data manipulation, config changes |
| `execute_javascript` | Run JavaScript in Claude's context | Cross-context scripting, data extraction |
| `execute_sql` | Execute database queries | Data access, modification, or destruction |

- **Principle of least privilege** — Extensions should only request the tools they need. An extension with `run_command` has equivalent access to a shell session.
- **Combined risk** — An unsigned extension with dangerous tools is the highest-risk combination: unverified code with powerful capabilities.

### Extension Governance

#### `Extension blocklist is empty` (WARN)

**What it detects:** The `extensions-blocklist.json` file exists but contains zero entries.

**Why it matters:** The blocklist is a negative governance control — it prevents specific extensions from being installed.

- **No known-bad protection** — An empty blocklist means no extensions have been explicitly prohibited, even if known-bad or revoked extensions exist.
- **Defence in depth** — The blocklist complements the allowlist. Even with an allowlist enabled, a blocklist provides an additional layer for rapidly blocking a compromised extension before the allowlist is updated.
- **Incident response** — During a security incident involving a malicious extension, the blocklist is the fastest way to prevent it from being (re)installed across the fleet.

### Plugins

#### `Remote plugin deployed` (REVIEW)

**What it detects:** A plugin exists in `remote_cowork_plugins/manifest.json`, indicating it was deployed by an organisation administrator.

**Why it matters:** Remote plugins are pushed to user machines via marketplace infrastructure. Unlike user-installed plugins, users don't choose to install them.

- **Authorisation** — Verify that the deployer (`installedBy`) is an authorised administrator. Unexpected remote plugins could indicate a compromised admin account or an unauthorised deployment.
- **Scope creep** — Remote plugins apply to all users in the org scope. A plugin deployed for one team's use case is available to everyone.
- **Skills and tools** — Remote plugins can include skills (SKILL.md prompt files) and tools that execute in users' Claude sessions. Review the plugin's skill count and capabilities.
- **Severity: REVIEW** — This is not inherently a problem (it's the intended deployment mechanism), but each remote plugin should be verified as expected.

### Scheduled Tasks

#### `Active scheduled task` (WARN)

**What it detects:** A task in `scheduled-tasks.json` has `enabled == true`.

**Why it matters:** Each active scheduled task runs on a cron-like schedule and executes the instructions in its associated SKILL.md file.

- **Unattended execution** — The task runs without user interaction. The SKILL.md prompt defines what Claude does, which tools it uses, and what data it accesses.
- **Cron translation** — CLAUDIT translates the cron expression to English (e.g. `0 9 * * 1-5` becomes "At 09:00, Monday through Friday") so reviewers don't need to parse cron syntax.
- **Review action** — For each active task, review: What does the SKILL.md instruct Claude to do? What connectors/tools does it have access to? Is the schedule appropriate? Who created it?

### Connectors

#### `Web connector(s) authenticated` (INFO)

**What it detects:** One or more OAuth-authenticated web service connectors are active in `remoteMcpServersConfig` within session `local_*.json` files.

**Why it matters:** Each web connector grants Claude access to an external service (Slack, Gmail, Notion, Jira, GitHub, etc.) using the user's OAuth credentials.

- **Blast radius** — A prompt injection or malicious skill can leverage any authenticated connector. If Claude has Slack, Gmail, and Jira access, a single attack can read/write across all three.
- **Overprivileged access** — Users may authenticate connectors they no longer need. Each unused connector is unnecessary attack surface.
- **Data flow** — Connectors enable Claude to read from and write to external services. In conversations involving sensitive data, connected services may receive that data.
- **Audit trail** — Actions taken via connectors appear as the user's actions in those services. There is typically no way to distinguish "user did this" from "Claude did this on user's behalf" in service audit logs.
- **Severity: INFO** — Connectors are expected functionality, but the count and specific services should be reviewed.

### Security (App Config)

#### `Unencrypted OAuth token in plaintext config` (WARN)

See [App Config section above](#unencrypted-oauth-token-in-plaintext-config-warn).

#### `Extension allowlist DISABLED` (WARN)

See [App Config section above](#extension-allowlist-disabled-warn).

#### `Extension blocklist is empty` (WARN)

See [Extension Governance section above](#extension-blocklist-is-empty-warn).

### Claude Code Settings

#### `Permissions granted` (INFO)

**What it detects:** The `permissions.allow` array in `~/.claude/settings.json` contains one or more permission grant strings.

**Why it matters:** Claude Code permission grants control which tools Claude Code can use without prompting the user for confirmation.

- **Broad grants** — Permissions like `Bash(*)` or `Edit(*)` effectively give Claude Code unrestricted access to shell execution or file editing. Review whether wildcard grants are appropriate.
- **Persistent** — Unlike per-session approvals, settings.json grants persist across all sessions and projects.
- **Scope** — These are user-level grants. Project-level grants in `.claude/settings.json` or `.claude/settings.local.json` within repositories are not currently audited.
- **Severity: INFO** — Permission grants are expected configuration, but overly broad grants should be reviewed.

### File Permissions

#### `Insecure permissions on [file]` (WARN or CRITICAL)

**What it detects:** A config file has permissions that allow access beyond the file owner.

| Condition | Severity | Meaning |
|-----------|----------|---------|
| Group-writable or world-writable | **CRITICAL** | Other users or processes can modify the file |
| Group-readable or world-readable | **WARN** | Other users or processes can read the file |

**Files checked:** `claude_desktop_config.json`, `config.json`, `extensions-installations.json`, `extensions-blocklist.json`, `~/.claude/settings.json`, all files in `Claude Extensions Settings/`, `Cookies`, `Cookies-journal`.

**Why it matters:**

- **Config tampering (writable)** — If a config file is writable by other users or groups, an attacker with any account on the system can: add malicious MCP servers, install extensions, modify scheduled task prompts, or inject OAuth tokens. This is a **CRITICAL** finding because it allows privilege escalation through Claude.
- **Credential exposure (readable)** — If `config.json` (which may contain OAuth tokens) or `Cookies` files are world-readable, any process on the system can harvest credentials.
- **macOS multi-user** — On shared Macs (lab environments, kiosks, developer machines with multiple accounts), file permissions are the primary isolation boundary between users.
- **Remediation** — Set all Claude config files to mode `600` (`chmod 600 <file>`), which restricts access to the file owner only.

### Runtime State

#### `Claude is running` (INFO)

**What it detects:** One or more Claude-related processes are found via `pgrep`.

**Why it matters:** Informational — confirms Claude is active on the endpoint. Useful for fleet-wide inventory to understand deployment scope.

#### `Sleep prevention assertion by Claude/Electron` (WARN)

**What it detects:** `pmset -g assertions` shows an active power management assertion from a Claude or Electron process.

**Why it matters:** This is the runtime confirmation of the `keepAwakeEnabled` setting. Even if the setting is off, a bug or different code path could create a sleep assertion.

- **Same risks as `keepAwakeEnabled`** — energy policy violation, physical security, endpoint compliance.
- **Process-level evidence** — This finding includes the specific assertion details from `pmset`, providing the PID and assertion type for investigation.

#### `Claude-related crontab entry found` (WARN)

**What it detects:** The user's crontab (via `crontab -l`) contains an entry referencing "claude" (case-insensitive).

**Why it matters:** Crontab entries are a classic persistence mechanism on Unix systems.

- **Out-of-band persistence** — Claude-related crontab entries operate outside Claude's own scheduling system, making them harder to discover through normal Claude configuration review.
- **Unexpected automation** — Legitimate Claude usage should not require crontab entries. Their presence may indicate: manual automation by the user, a compromised extension writing to crontab, or tooling that wraps Claude in cron jobs.
- **Investigation** — Review the full crontab entry (included in the finding detail) to determine what command is being executed and whether it is authorised.

#### `Claude LaunchAgent(s) found` (WARN)

**What it detects:** `.plist` files in `~/Library/LaunchAgents/` with "claude" in the filename.

**Why it matters:** LaunchAgents are macOS's native mechanism for running programs at login and keeping them running.

- **Persistence** — A LaunchAgent ensures Claude (or a Claude-related process) starts automatically and restarts if killed. This is a stronger persistence mechanism than crontab.
- **Expected vs unexpected** — Claude Desktop may legitimately install a LaunchAgent for auto-update or background sync. Verify that any found agents match known Anthropic-signed components.
- **Tampering** — If the LaunchAgent plist is writable by other users (see File Permissions), an attacker could modify it to execute arbitrary code at login.

#### `Debug directory is large` (WARN)

**What it detects:** The `~/Library/Application Support/Claude/debug/` directory exceeds 100 MB.

**Why it matters:**

- **Disk space** — Large debug directories consume disk, particularly on machines with limited storage.
- **Sensitive data in logs** — Debug logs may contain conversation fragments, tool outputs, API responses, or other sensitive data that persists on disk indefinitely.
- **Data retention** — Depending on your data retention policy, debug logs containing conversation data may need to be rotated or purged.

### Cookies

#### Cookie file presence and permissions

**What it detects:** The existence and file permissions of `Cookies` and `Cookies-journal` in the Claude Desktop directory.

**Why it matters:** Claude Desktop uses an Electron-based browser environment that maintains its own cookie store.

- **Session tokens** — Cookies may contain session tokens for authenticated web services accessed via Claude's browser capabilities.
- **Permission exposure** — If cookie files are readable by other users, session tokens could be harvested for session hijacking.
- **Forensics** — The presence of cookie files confirms that Claude's browser environment has been used, which may be relevant for incident investigation.

## Quick Start

### Local Run

```bash
# Default: audit current user, ASCII output
zsh claude_audit.sh

# Warnings only
zsh claude_audit.sh -q

# JSON for SIEM
zsh claude_audit.sh --json

# Standalone HTML report
zsh claude_audit.sh --html

# Specific user
zsh claude_audit.sh --user jsmith

# All users (requires appropriate permissions)
zsh claude_audit.sh --all-users
```

### MDM Deployment

The script auto-detects when running as root (uid 0) and scans all users with Claude data — no flags needed.

**FleetDM:**
Upload `claude_audit.sh` as a script. Run with `--json` for structured output or `--html` for per-endpoint reports.

**Jamf Pro:**
Add as a script payload in a policy. The script runs as root and automatically discovers all users.

**CrowdStrike RTR:**
Upload the script to the target host, then run via `runscript`. RTR runs as root so all users are scanned automatically.

```bash
# Upload to target, then run with HTML output
runscript -Raw=```zsh /Users/<username>/claude_audit.sh --html /Users/<username>/claude_audit_report.html``` -Timeout=120

# Retrieve the report (RTR will 7z-compress the download)
get /Users/<username>/claude_audit_report.html

# Or get JSON directly in the RTR console
runscript -Raw=```zsh /Users/<username>/claude_audit.sh --json``` -Timeout=120
```

**Kandji / Mosyle / Addigy:**
Deploy as a custom script. No configuration required.

### Requirements

- **macOS** (Darwin) — the only supported platform
- **zsh** — ships with every Mac since macOS Catalina (10.15)
- **jq** — install via `brew install jq` or bundle with your MDM payload

## Output Formats

### ASCII (default)

Terminal output with ANSI colour, Unicode box-drawing tables, and severity indicators. Suitable for interactive use and RTR sessions.

```
╔══════════════════════════════════════════════════════════════════╗
║                 CLAUDIT — CLAUDE SECURITY AUDIT                  ║
║                     2026-03-16 16:01:27 GMT                      ║
║                Host: ML715C9Q3V | User: edmerrett                ║
╚══════════════════════════════════════════════════════════════════╝

──── SUMMARY ──────────────────────────────────────────────────────
  Scheduled tasks: 1  |  MCP servers: 1  |  Extensions: 2
  Plugins: 1 installed, 1 remote, 2 cached  |  Connectors: 11 web, 14 not connected
  Skills: 39  |  Findings: 25 warnings, 1 items to review

──── SECURITY FINDINGS ────────────────────────────────────────────
  [WARN] Unencrypted OAuth token in plaintext config
  [WARN] Extension allowlist DISABLED: dxt:allowlistEnabled
  [WARN] Extension blocklist is empty — no governance controls
  [WARN] Sleep prevention assertion by Claude/Electron
```

### JSON (`--json`)

Structured output for SIEM ingestion, Splunk, Elastic, or custom tooling. Sensitive fields are automatically redacted. Multi-user scans produce a JSON array.

```json
{
  "timestamp": "2026-03-16 16:03:44 GMT",
  "hostname": "ML715C9Q3V",
  "username": "edmerrett",
  "findings": [
    {
      "severity": "WARN",
      "section": "Desktop Settings",
      "message": "keepAwakeEnabled is ON — prevents macOS from sleeping"
    }
  ],
  "warn_count": 25,
  "info_count": 3,
  "critical_count": 0,
  "extensions": [...],
  "plugins": [...],
  "mcp_servers": [...],
  "connectors": [...],
  "skills": [...],
  "scheduled_tasks": [...]
}
```

### HTML (`--html`)

Standalone dark-themed report with collapsible sections. Created with mode `0600`. Auto-named per user when scanning multiple users.

```bash
zsh claude_audit.sh --html                    # claude_audit_edmerrett_20260316_160127.html
zsh claude_audit.sh --html report.html        # report.html
zsh claude_audit.sh --html --all-users        # claude_audit_edmerrett_*.html, claude_audit_jsmith_*.html
```

## Interpreting Findings

### Severity Levels

| Severity | Meaning | Example |
|----------|---------|---------|
| **CRITICAL** | Immediate risk requiring action | Config file is world-writable |
| **WARN** | Configuration that increases risk surface | OAuth token in plaintext, unsigned extensions, autonomous execution enabled |
| **REVIEW** | Requires human judgement | Remote plugin deployed by org admin, MCP server present |
| **INFO** | Informational, no action needed | Claude is running, permissions granted to Claude Code |

### High-Value Findings to Watch

**Autonomous execution active** — `coworkScheduledTasksEnabled=true` means Claude runs tasks on cron schedules without user interaction. Review each task's SKILL.md for prompt content and delivery targets.

**Unsigned extensions with dangerous tools** — Extensions with `write_file`, `edit_file`, `execute_javascript`, or `run_command` that aren't signed could be tampered with. Enable the extension allowlist.

**Extension allowlist disabled** — Without an allowlist, any extension can be installed. This is the DXT equivalent of allowing unsigned code execution.

**Remote plugins** — Org-deployed plugins appear on user machines via the marketplace. Unexpected remote plugins may indicate unauthorized deployment or a compromised marketplace source.

**Web connectors** — Each authenticated connector (Slack, Gmail, Notion, Jira, etc.) grants Claude access to that service using the user's credentials. Verify each is expected and revoke unused ones.

**MCP servers** — Model Context Protocol servers execute with Claude's permissions and can access external services. Each one is an arbitrary command execution surface.

**OAuth token in plaintext** — This is an Anthropic application default. The token sits in `config.json` readable by any process running as the user.

## SIEM Integration

### Splunk

```bash
# Run on endpoints, forward JSON to Splunk HTTP Event Collector
zsh claude_audit.sh --json | curl -k https://splunk:8088/services/collector/event \
  -H "Authorization: Splunk YOUR_TOKEN" \
  -d @-
```

### Elastic

```bash
# Index directly
zsh claude_audit.sh --json | curl -X POST "https://elastic:9200/claudit/_doc" \
  -H "Content-Type: application/json" -d @-
```

### FleetDM Query

Deploy as a script and query results across your fleet. The `--json` output can be parsed by FleetDM's script result handling.

### Detection Rules

Key fields to alert on:

```
findings[].severity == "CRITICAL"           # Immediate action
warn_count > 20                             # High finding count
extensions[].signed == false                # Unsigned extensions
extensions[].dangerous_tools != []          # Dangerous tool grants
plugins[].source == "remote"                # Org-deployed plugins
scheduled_tasks[].enabled == true           # Active autonomous tasks
mcp_servers | length > 0                    # MCP server presence
connectors[].category == "web" | length > 5 # Many authenticated services
```

## Security Properties

- **Read-only** — the script never writes to, modifies, or deletes any audited file
- **No network access** — all data is collected from local filesystem and system commands
- **Sensitive data redacted** — OAuth tokens, API keys, secrets, and MCP environment variable values are replaced with `[REDACTED]` in all output formats
- **Minimal privileges** — runs as the current user by default; root is only needed for multi-user scans
- **Single file** — no dependencies to supply-chain attack (except `jq`)
- **Auditable** — the entire tool is one readable script

## License

Internal security tooling. See your organisation's policy for distribution.
