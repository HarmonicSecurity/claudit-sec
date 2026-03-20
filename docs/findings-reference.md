# 📋 CLAUDIT-SEC Findings Reference

> **A comprehensive reference for every check performed by CLAUDIT-SEC v2.2.0**
>
> This document is intended for security teams, compliance reviewers, and administrators who need to understand exactly what CLAUDIT inspects, why each check matters, and how to respond when findings are flagged.

---

## 📑 Table of Contents

1. [🖥️ Desktop Settings](#1--desktop-settings)
2. [🤖 Cowork Settings](#2--cowork-settings)
3. [🔌 MCP Servers](#3--mcp-servers)
4. [🧩 Extensions (DXT)](#4--extensions-dxt)
5. [📂 Extension Settings](#5--extension-settings)
6. [🛡️ Extension Governance (Blocklist & Allowlist)](#6--extension-governance-blocklist--allowlist)
7. [🔗 Plugins](#7--plugins)
8. [🪝 Plugin Hooks](#8--plugin-hooks)
9. [🌐 Connectors](#9--connectors)
10. [🎯 Skills](#10--skills)
11. [⏰ Scheduled Tasks](#11--scheduled-tasks)
12. [⚙️ App Config (config.json)](#12--app-config-configjson)
13. [💻 Claude Code Settings](#13--claude-code-settings)
14. [🏃 Runtime State](#14--runtime-state)
15. [🍪 Cookies](#15--cookies)
16. [📊 Severity Level Reference](#16--severity-level-reference)

---

## 🔑 How to Read This Document

Each check follows a consistent format:

- **What** — The file, setting, or system state being inspected
- **Why it matters** — Risk, compliance, and/or AI enablement implications
- **Severity** — The level assigned (`CRITICAL`, `WARN`, `INFO`, `REVIEW`) and the rationale
- **Recommendation** — What action to take if this finding appears

CLAUDIT is a **read-only** tool — it never modifies any audited files. All findings are observational.

---

## 1. 🖥️ Desktop Settings

**Source file:** `~/Library/Application Support/Claude/claude_desktop_config.json` → `preferences`

These checks examine user-facing preferences in Claude Desktop that affect system behavior, power management, and UI exposure.

---

### 🔋 keepAwakeEnabled

- **What**: Checks whether `preferences.keepAwakeEnabled` is set to `true` in the desktop config. When enabled, Claude Desktop uses a macOS power assertion to prevent the machine from sleeping.
- **Why it matters**:
  - 🔴 **Risk**: A machine that never sleeps stays network-reachable and unlocked for longer periods, increasing the attack surface for remote exploitation or physical access. On laptops, it drains battery and can cause overheating.
  - 📜 **Compliance**: Many endpoint hardening baselines (CIS macOS, NIST 800-53 AC-11) require idle sleep/lock timeouts. An app overriding sleep policy can violate these controls.
  - 🤖 **AI enablement**: This setting exists so that long-running Cowork/agentic tasks complete without being interrupted by macOS sleep. Understanding whether it is enabled tells you if the user is running autonomous sessions.
- **Severity**: ⚠️ `WARN` — Overriding system power management is a security-relevant configuration change that merits review.
- **Recommendation**: Disable unless the user specifically needs Claude to run unattended overnight. Ensure compensating controls (screen lock, FileVault) are in place if left enabled.

---

### 📊 menuBarEnabled, sidebarMode, quickEntryShortcut

- **What**: Reads the `menuBarEnabled`, `sidebarMode`, and `quickEntryShortcut` values from desktop preferences. These control whether Claude appears in the macOS menu bar, the sidebar display mode, and the global keyboard shortcut for quick entry.
- **Why it matters**:
  - 🔍 **Visibility**: These are informational settings that help administrators understand the Claude Desktop UX configuration. A menu bar presence or global keyboard shortcut indicates active daily use.
  - 🤖 **AI enablement**: Quick entry shortcuts and sidebar modes indicate how deeply Claude is integrated into the user's workflow.
- **Severity**: These are **displayed in the report** but do **not** generate a finding (no `add_finding` call). They appear in the Desktop Settings section of the output for asset inventory purposes.
- **Recommendation**: No action required. These are informational data points.

---

## 2. 🤖 Cowork Settings

**Source files:** `claude_desktop_config.json` → `preferences`, `cowork_settings.json` (per session)

Cowork is Claude Desktop's agentic mode. These checks examine settings that control autonomous behavior — tasks that run without direct user interaction.

---

### ⏱️ Scheduled Tasks Enabled (coworkScheduledTasksEnabled)

- **What**: Checks whether `preferences.coworkScheduledTasksEnabled` is `true`. This is the master switch that allows Cowork scheduled tasks to execute on a cron schedule.
- **Why it matters**:
  - 🔴 **Risk**: When enabled, Claude can execute tasks autonomously on a schedule — reading files, calling MCP tools, performing web searches, and interacting with connected services without a human triggering each action. This is the single most significant autonomous capability in Claude Desktop.
  - 📜 **Compliance**: Autonomous AI agents running on employee machines may require governance review under AI use policies, especially if they access sensitive data or external services.
  - 🤖 **AI enablement**: This is the core toggle for Cowork's "background agent" capability. Understanding whether it is enabled is critical for assessing the scope of AI activity on a machine.
- **Severity**: ⚠️ `WARN` — Autonomous task execution is a high-impact capability that should be intentionally enabled and reviewed.
- **Recommendation**: Verify that the user needs autonomous scheduled tasks. Review the Scheduled Tasks section to understand what tasks are defined and what they do.

---

### 🖥️ Code Desktop Scheduled Tasks (ccdScheduledTasksEnabled)

- **What**: Checks whether `preferences.ccdScheduledTasksEnabled` is `true`. This enables scheduled tasks for Code Desktop (a variant of Claude Desktop focused on coding).
- **Why it matters**:
  - 🔴 **Risk**: Same as `coworkScheduledTasksEnabled` — enables autonomous task execution, but specifically for coding-focused tasks which may modify source code, run builds, or interact with development tooling.
  - 📜 **Compliance**: Code-modifying autonomous agents may fall under software supply chain security requirements.
  - 🤖 **AI enablement**: Indicates the user has set up autonomous coding workflows.
- **Severity**: ⚠️ `WARN` — Autonomous code execution tasks warrant review.
- **Recommendation**: Same as above. Review defined scheduled tasks and their prompts to understand scope.

---

### 🌐 Web Search Enabled (coworkWebSearchEnabled)

- **What**: Checks whether `preferences.coworkWebSearchEnabled` is `true`. When enabled, Claude Cowork can autonomously search the internet during task execution.
- **Why it matters**:
  - 🔴 **Risk**: Web search gives Claude autonomous internet access — it can reach arbitrary URLs, potentially exposing internal prompts or context to external web services. Search queries could inadvertently leak sensitive information.
  - 📜 **Compliance**: Organizations with data loss prevention (DLP) policies or network segmentation requirements should know when AI tools have outbound internet access. This may violate "air-gapped" or "no external calls" requirements.
  - 🤖 **AI enablement**: Web search significantly expands Claude's capabilities, allowing it to retrieve current information, check documentation, and research topics. Understanding its status helps assess the scope of AI data flows.
- **Severity**: ⚠️ `WARN` — Autonomous internet access is a significant capability expansion that should be intentionally configured.
- **Recommendation**: Disable if the organization requires AI tools to operate without external internet access. If enabled, ensure network monitoring covers Claude's outbound traffic.

---

### 🌍 Allow All Browser Actions (allowAllBrowserActions)

- **What**: Checks whether `preferences.allowAllBrowserActions` is `true`. When enabled, Claude can browse and interact with any website in Chrome without asking for user approval per action.
- **Why it matters**:
  - 🔴 **Risk**: With this enabled, Claude can navigate to arbitrary URLs, fill forms, click buttons, and execute JavaScript in the browser without per-action user consent. This expands the attack surface to include any website Claude can reach — a compromised or prompt-injected session could interact with sensitive web applications (banking, admin panels, internal tools) without the user being prompted.
  - 📜 **Compliance**: Unrestricted browser automation may violate acceptable use policies, especially in environments where web access is governed. Autonomous interactions with third-party websites can create unintended data sharing or contractual exposure.
  - 🤖 **AI enablement**: This setting is designed for power users who want seamless browser automation without constant approval prompts. It is a convenience/security trade-off.
- **Severity**: ⚠️ `WARN` — Unrestricted browser actions represent a significant capability expansion.
- **Recommendation**: Disable unless the user specifically needs autonomous browser interaction. When enabled, ensure network-level controls (proxy, DNS filtering) limit reachable websites. Review the Chrome Control extension's allowed actions.

---

### 🌐 Egress Allowed Domains (egressAllowedDomains)

- **What**: Reads `egressAllowedDomains` from `local_*.json` session files. This field controls which domains the Cowork VM can reach over the network. A value of `["*"]` means unrestricted egress; a specific domain list means traffic is restricted to those domains only.
- **Why it matters**:
  - 🔴 **Risk**: When set to `["*"]`, the Cowork sandbox has unrestricted network egress — it can connect to any domain on the internet. This means autonomous code execution inside the VM can exfiltrate data to arbitrary endpoints, download malicious payloads, or interact with unauthorized services. A restricted domain list is the primary network boundary control for the Cowork VM.
  - 📜 **Compliance**: Network segmentation and egress filtering are fundamental security controls (CIS, NIST 800-53 SC-7). Unrestricted egress from an AI agent's sandbox violates these controls.
  - 🤖 **AI enablement**: Egress domains define what external resources are available to Cowork sessions. Development workflows may need access to package registries (npmjs.org, pypi.org), while more restricted sessions should be limited to specific domains.
- **Severity**: ⚠️ `WARN` if `["*"]` (unrestricted), ℹ️ `INFO` if restricted to specific domains.
- **Recommendation**: If egress is unrestricted (`["*"]`), investigate whether this is intentional. Work with the organization to define an appropriate domain allowlist. For restricted sessions, review the domain list to ensure only necessary domains are included.

---

### 🔇 Disabled MCP Tools (enabledMcpTools)

- **What**: Reads `enabledMcpTools` from `local_*.json` session files and identifies tools explicitly set to `false` (disabled). Reports the total count and specifically calls out dangerous tools that have been disabled (e.g., `write_file`, `edit_file`, `execute_javascript`, `run_command`).
- **Why it matters**:
  - 🔍 **Visibility**: Disabled MCP tools show that the user or system has intentionally restricted certain capabilities. This is a positive security signal — it means dangerous tools have been turned off. However, the list also reveals what tools are available (everything not in the disabled list is implicitly enabled).
  - 🤖 **AI enablement**: Users can fine-tune which MCP tools are active per session. The disabled list reflects conscious security decisions about tool access.
- **Severity**: ℹ️ `INFO` — Disabling tools is a positive action, but the inventory is useful for understanding the security posture.
- **Recommendation**: Review the disabled tools list to confirm dangerous tools are disabled as expected. Verify that no critical restrictions have been removed.

---

### 🔌 Enabled Plugins, Marketplaces, Network Mode

- **What**: Reads `enabledPlugins` (map of plugin names to booleans), `extraKnownMarketplaces` (custom marketplace sources), and the network mode from `cowork_settings.json` and `config.json`.
- **Why it matters**:
  - 🔍 **Visibility**: Enabled plugins show which integrations are active. Custom marketplaces indicate non-standard plugin sources. Network mode indicates proxy or restricted network configurations.
  - 🤖 **AI enablement**: The plugin and marketplace configuration defines the ecosystem of tools available to Claude's agentic mode.
- **Severity**: These are **displayed in the report** but do **not** generate findings individually. They appear for asset inventory and context.
- **Recommendation**: Review enabled plugins against organizational approved software lists. Verify custom marketplace sources are legitimate and expected.

---

## 3. 🔌 MCP Servers

**Source file:** `claude_desktop_config.json` → `mcpServers`

MCP (Model Context Protocol) servers are external processes that Claude launches to extend its capabilities. Each server is a running process with its own command, arguments, and environment variables.

---

### 🖥️ MCP Server Inventory

- **What**: Enumerates all MCP servers configured under `mcpServers` in the desktop config. For each server, CLAUDIT captures the server name, the command it runs, its arguments (with secrets redacted), and the names of any environment variables (values are never captured).
- **Why it matters**:
  - 🔴 **Risk**: MCP servers are arbitrary executables launched by Claude Desktop with the user's full permissions. They can execute any command, access the filesystem, make network connections, and interact with external APIs. A malicious or misconfigured MCP server is one of the highest-risk vectors in the Claude ecosystem. Arguments matching patterns like `sk-`, `key=`, `token=`, `secret=`, or `password=` are automatically redacted.
  - 📜 **Compliance**: MCP servers are effectively third-party code execution. They should be inventoried and approved as part of software asset management. Environment variable names (not values) are reported to identify what credentials each server accesses.
  - 🤖 **AI enablement**: MCP servers are how Claude connects to databases, APIs, filesystems, and custom tools. Understanding which servers are configured reveals the full scope of Claude's capabilities on a given machine.
- **Severity**: MCP servers are **displayed in a table** and flagged with a `[REVIEW]` note in the ASCII/HTML output. No individual `add_finding` is generated per server — the entire section is presented for manual review.
- **Recommendation**: Verify each MCP server is expected and approved. Check that commands point to known, trusted binaries. Review environment variable names to ensure credentials are appropriate. Remove any servers that are no longer needed.

---

## 4. 🧩 Extensions (DXT)

**Source file:** `~/Library/Application Support/Claude/extensions-installations.json`

DXT extensions are packaged plugins for Claude Desktop that provide tools and capabilities. They can be signed (verified by Anthropic) or unsigned (sideloaded).

---

### ✍️ Unsigned Extension

- **What**: Checks the `signatureInfo.status` field of each installed extension. If the status is `"unsigned"`, this finding is generated.
- **Why it matters**:
  - 🔴 **Risk**: Unsigned extensions have no cryptographic verification of their origin or integrity. They could be modified, tampered with, or created by untrusted parties. An unsigned extension can contain arbitrary code that runs with Claude Desktop's permissions.
  - 📜 **Compliance**: Extension signing is a governance control. Organizations that require code signing for all executable components should flag unsigned extensions.
  - 🤖 **AI enablement**: Understanding the signing status helps distinguish between vetted marketplace extensions and developer/sideloaded extensions.
- **Severity**: ⚠️ `WARN` — Unsigned extensions bypass integrity verification and should be reviewed.
- **Recommendation**: Review the extension's purpose and source. Prefer signed extensions from the official marketplace. If the unsigned extension is a legitimate development build, document the exception.

---

### ⚡ Extension with Dangerous Tools

- **What**: Checks each extension's declared tools against a hardcoded list of dangerous tool names: `execute_javascript`, `write_file`, `edit_file`, `run_command`, `execute_sql`. If any extension declares one or more of these tools, this finding is generated.
- **Why it matters**:
  - 🔴 **Risk**: These tools represent high-privilege operations — arbitrary JavaScript execution, filesystem writes, system command execution, and SQL execution. An extension with these tools can modify files, run arbitrary commands, execute code, and alter databases. Combined with Claude's autonomous capabilities, this creates significant risk.
  - 📜 **Compliance**: Tools that can execute arbitrary code or modify data are critical from a change control and least-privilege perspective.
  - 🤖 **AI enablement**: Dangerous tools are often necessary for legitimate development workflows (e.g., a coding assistant that can edit files). The finding ensures visibility into which extensions have these elevated capabilities.
- **Severity**: ⚠️ `WARN` — Dangerous tools represent elevated capability that should be explicitly approved.
- **Recommendation**: Verify that each dangerous tool is required for the extension's intended purpose. Consider whether the extension should be scoped more narrowly. Ensure the extension is signed if it declares dangerous tools.

---

## 5. 📂 Extension Settings

**Source directory:** `~/Library/Application Support/Claude/Claude Extensions Settings/*.json`

Per-extension settings files contain user-configured options, including filesystem access permissions.

---

### 📁 Allowed Directories

- **What**: For each extension settings JSON file, CLAUDIT reads `userConfig.allowed_directories` (or `userConfig.allowedDirectories`) — the list of filesystem paths the extension is permitted to access.
- **Why it matters**:
  - 🔴 **Risk**: Allowed directories define the blast radius of an extension. An extension with `"/"` as an allowed directory has full filesystem access. Broad directory permissions combined with dangerous tools (write_file, edit_file) can allow an extension to read or modify any file on the system.
  - 📜 **Compliance**: Filesystem access scoping is a least-privilege control. Overly broad directory access should be narrowed.
  - 🤖 **AI enablement**: Allowed directories show what parts of the filesystem Claude can interact with through each extension.
- **Severity**: These are **displayed in the report** (in the Extensions section output) but do **not** generate a separate `add_finding` call. The data is presented for manual review.
- **Recommendation**: Review allowed directories for each extension. Apply the principle of least privilege — restrict to only the directories the extension needs. Avoid allowing `/`, `~`, or `~/Documents` unless absolutely necessary.

---

## 6. 🛡️ Extension Governance (Blocklist & Allowlist)

**Source files:** `extensions-blocklist.json`, `config.json` (keys containing `dxt:allowlistEnabled`)

These checks examine organizational governance controls over extensions.

---

### 🚫 Extension Blocklist Empty

- **What**: Reads `extensions-blocklist.json` and counts the total number of blocked extension entries. If the file exists but contains zero entries, this finding is generated.
- **Why it matters**:
  - 🔴 **Risk**: An empty blocklist means there are no governance restrictions on which extensions can be installed. Any extension — including known-malicious or unapproved ones — can be added without restriction.
  - 📜 **Compliance**: Extension governance is a key control for organizations. CIS benchmarks and SOC 2 controls expect managed software inventories with allow/deny lists. An empty blocklist suggests governance has not been configured.
  - 🤖 **AI enablement**: The blocklist is how administrators prevent specific extensions from being installed. Its absence means no negative controls are in place.
- **Severity**: ⚠️ `WARN` — Lack of governance controls is a policy gap that should be addressed.
- **Recommendation**: Populate the blocklist with extensions that are not approved for the organization. Establish a governance process for reviewing and approving new extensions.

---

### 🔓 Extension Allowlist Disabled

- **What**: Searches `config.json` for keys containing `dxt:allowlistEnabled`. For each key found with a value of `"false"`, this finding is generated. The key names typically include an organization scope identifier.
- **Why it matters**:
  - 🔴 **Risk**: When the allowlist is disabled, any extension can be installed without going through an approval process. This removes the positive governance control (allow-only-approved) and relies solely on the blocklist (deny-known-bad), which is a weaker posture.
  - 📜 **Compliance**: Allowlisting is the gold standard for software governance. Disabling it for any organization scope represents a reduction in security posture.
  - 🤖 **AI enablement**: The allowlist controls which extensions are available to users. Disabling it gives users unrestricted extension installation capability.
- **Severity**: ⚠️ `WARN` — Disabling the allowlist weakens organizational control over the extension ecosystem.
- **Recommendation**: Re-enable the allowlist and populate it with approved extensions. If disabled intentionally for testing, document the exception and set a review date.

---

## 7. 🔗 Plugins

**Source files:** `installed_plugins.json`, `remote_cowork_plugins/manifest.json`, marketplace directories, cache directories (per session)

Plugins extend Claude Cowork's capabilities. They come in three categories: installed (user-chosen from a marketplace), remote (org-deployed by administrators), and cached (downloaded but not necessarily installed).

---

### 📡 Remote Plugin Deployed

- **What**: For each plugin found in `remote_cowork_plugins/manifest.json`, CLAUDIT generates a finding listing the plugin name, version, deployer, plugin ID, and marketplace source.
- **Why it matters**:
  - 🔴 **Risk**: Remote plugins are deployed by an organization administrator and pushed to the user's machine. While this is a legitimate distribution mechanism, it means code is being installed on the user's machine by a third party (the org admin). If the deployment pipeline is compromised, malicious plugins could be pushed.
  - 📜 **Compliance**: Remote plugins should be part of the organization's software inventory and approved through the standard software approval process.
  - 🤖 **AI enablement**: Remote plugins represent the organization's chosen set of AI capabilities. They often provide specialized integrations (internal tools, knowledge bases, workflow automation).
- **Severity**: 🔍 `REVIEW` — Remote plugins are expected in managed environments but should be verified against the organization's approved plugin list.
- **Recommendation**: Verify each remote plugin against the organization's approved software list. Confirm the deployer (`installedBy`) is a legitimate administrator. Review the plugin's skills and capabilities.

---

### 📦 Installed and Cached Plugins

- **What**: Enumerates installed plugins (from `installed_plugins.json`) and cached plugins (from `cowork_plugins/cache/`). For each, CLAUDIT captures name, version, source marketplace, scope, author, description, and skill count.
- **Why it matters**:
  - 🔍 **Visibility**: The installed plugin inventory shows what capabilities the user has added. Cached plugins show what has been downloaded — even if not currently installed, cached code on disk could be relevant for forensics or compliance audits.
  - 🤖 **AI enablement**: Each plugin adds tools and skills that Claude can use. The full inventory defines the scope of Claude's autonomous capabilities.
- **Severity**: These are **displayed in the report** but do **not** generate individual findings. They appear in the Plugins section tables.
- **Recommendation**: Review installed plugins against organizational approved lists. Clean up cached plugins that are no longer needed.

---

### 🏪 Marketplace Availability

- **What**: Lists plugins available in the marketplace catalog that are NOT installed or deployed. This is an inventory of what could be installed.
- **Why it matters**:
  - 🔍 **Visibility**: Knowing what is available but not yet installed provides context for future risk — users could add these plugins at any time.
- **Severity**: **Informational display only** — no finding generated.
- **Recommendation**: Use the allowlist/blocklist governance controls to restrict which marketplace plugins can be installed.

---

## 8. 🪝 Plugin Hooks

**Source files:** `hooks/hooks.json` inside plugin directories (cowork cached plugins, CC marketplace plugins, remote plugins)

Plugin hooks are shell commands that plugins register to run at specific lifecycle events during a Claude session. They execute automatically without user interaction.

---

### ⚠️ Plugin Hook Executing Commands

- **What**: Scans for `hooks/hooks.json` files inside plugin directories across 6 glob patterns (cowork cached plugins, CC marketplace plugins, remote plugins, and session-local copies). For each hooks file found, CLAUDIT extracts the hook events (`Stop`, `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`, etc.) and the shell commands they execute. Results are deduplicated by plugin name, event, and command.
- **Why it matters**:
  - 🔴 **Risk**: Plugin hooks are an arbitrary command execution channel. A hook registered on `PreToolUse` or `PostToolUse` runs a shell command **on every single tool call** — potentially hundreds of times per session. A hook on `Stop` runs when the session ends, and `UserPromptSubmit` runs on every user message. A malicious or compromised plugin could use hooks to:
    - **Exfiltrate data**: A `Stop` hook could `curl` session contents to an external server
    - **Modify behavior**: A `PreToolUse` hook could alter tool inputs or inject instructions
    - **Persist access**: Hooks run with the user's full permissions and can write files, install software, or modify system configuration
  - 📜 **Compliance**: Hooks are effectively background code execution triggered by AI agent activity. They should be inventoried and reviewed as part of software approval processes. Many organizations require visibility into all code execution paths.
  - 🤖 **AI enablement**: Hooks are a legitimate plugin capability for observability (logging, notifications), guardrails (security checks before tool use), and workflow automation (Slack notifications on task completion). The audit ensures visibility into what hooks are active.
- **Severity**: ⚠️ `WARN` — Plugin hooks represent a command execution channel that should be reviewed.
- **Recommendation**: Review each hook's command to understand what it does. Pay special attention to hooks that:
  - Make network calls (curl, wget, python scripts with HTTP)
  - Run on high-frequency events (PreToolUse, PostToolUse)
  - Reference external paths outside `${CLAUDE_PLUGIN_ROOT}`
  - Execute arbitrary interpreters (python3, node, bash) with complex scripts

  Remove or disable plugins with hooks that are not understood or not needed.

---

## 9. 🌐 Connectors

**Source files:** `local_*.json` (session files) → `remoteMcpServersConfig`, `.mcp.json` (from remote plugins), extensions, MCP servers

Connectors represent all the external services and integrations that Claude can interact with. CLAUDIT categorizes them as: **web** (OAuth-authenticated cloud services), **desktop** (local extensions and MCP servers), and **not_connected** (defined but not authenticated).

---

### 🔐 Web Connectors Authenticated

- **What**: Counts and lists all web connectors that have an active OAuth connection (found in `remoteMcpServersConfig` in session files). Reports the total count and names of authenticated services.
- **Why it matters**:
  - 🔴 **Risk**: Each authenticated web connector represents a live connection between Claude and an external service. Claude can use these connections to read from and write to external services autonomously. A compromised Claude session could access all connected services.
  - 📜 **Compliance**: OAuth connections to external services should be inventoried for data flow mapping. Each connection represents a data processing relationship that may need to be documented for GDPR, SOC 2, or other compliance frameworks.
  - 🤖 **AI enablement**: Web connectors are how Claude interacts with cloud services (e.g., Google Drive, Slack, GitHub). The authenticated connector list shows the full scope of Claude's external service access.
- **Severity**: ℹ️ `INFO` — Web connectors are a normal part of Claude's functionality, but the inventory is important for security awareness.
- **Recommendation**: Verify each authenticated connector is expected and approved. Review whether the connected services contain sensitive data. Revoke connections that are no longer needed.

---

### 🔌 Desktop Connectors and Not Connected

- **What**: Also enumerates desktop connectors (extensions and MCP servers acting as local integrations) and not-connected connectors (defined in remote plugin `.mcp.json` files but not authenticated).
- **Why it matters**:
  - 🔍 **Visibility**: Desktop connectors show local tool integrations. Not-connected connectors show integrations that are available but inactive — they could become active at any time if the user authenticates.
- **Severity**: **Displayed in the report** — no individual finding generated for desktop or not-connected connectors.
- **Recommendation**: Review desktop connectors as part of the MCP/Extensions review. For not-connected connectors, understand what they would access if authenticated and whether that is appropriate.

---

## 10. 🎯 Skills

**Source paths:** 9 different filesystem locations (see Architecture section)

Skills are SKILL.md files that define reusable prompts and instructions for Claude. They can be user-created, session-local, or provided by plugins.

---

### 🧑‍💻 User-Created Skills

- **What**: Scans 5 filesystem paths for user-created SKILL.md files:
  1. `~/Documents/Claude/Scheduled/*/SKILL.md` — Scheduled task skills
  2. `skills-plugin/<uid>/<oid>/skills/*/SKILL.md` — Cowork-created skills
  3. `~/.skills/skills/*/SKILL.md` — Alternative skills directory
  4. `~/.claude/skills/*/SKILL.md` — Claude Code user skills
  5. `<session>/local_*/.claude/skills/*/SKILL.md` — Session-local skills

  For each SKILL.md found, CLAUDIT parses YAML frontmatter to extract the skill name and description.
- **Why it matters**:
  - 🔴 **Risk**: Skills define Claude's behavior. A malicious skill could instruct Claude to exfiltrate data, modify files, or perform unauthorized actions. User-created skills are especially important because they are written directly by users (or injected by other tools) and are not subject to marketplace review.
  - 📜 **Compliance**: Skills represent the "standing instructions" given to an AI agent. For AI governance, organizations should know what instructions their AI tools are operating under.
  - 🤖 **AI enablement**: Skills are the building blocks of Cowork workflows. The inventory shows what custom behaviors have been configured.
- **Severity**: Skills are **displayed in the report** tables. No individual `add_finding` is called per skill — the entire inventory is presented for review.
- **Recommendation**: Review user-created skill contents, especially for scheduled tasks. Ensure skills do not contain instructions that violate organizational policies. Pay special attention to skills that reference external services or filesystem paths.

---

### 🔌 Plugin Skills

- **What**: Scans 3 filesystem paths for plugin-provided SKILL.md files:
  1. `<session>/remote_cowork_plugins/*/skills/*/SKILL.md` — Org-deployed plugin skills
  2. `<session>/cowork_plugins/cache/<mp>/<plugin>/<ver>/skills/*/` — Cached plugin skills
  3. `~/.claude/plugins/marketplaces/<mp>/{plugins,external_plugins}/<plugin>/skills/*/SKILL.md` — Claude Code marketplace plugin skills
- **Why it matters**:
  - 🔍 **Visibility**: Plugin skills show what behaviors each plugin adds to Claude. Since plugins are third-party code, understanding their skills helps assess the scope of third-party influence on Claude's behavior.
  - 🤖 **AI enablement**: Plugin skills are how plugins expose their capabilities. The inventory maps which skills come from which plugins.
- **Severity**: **Displayed in the report** — no individual finding generated. Shown in the Plugin Skills table with the associated plugin name.
- **Recommendation**: Review plugin skills as part of the broader plugin review. Focus on org-deployed (remote) plugin skills, as these affect all users.

---

## 11. ⏰ Scheduled Tasks

**Source file:** `scheduled-tasks.json` (per session)

Scheduled tasks are cron-scheduled autonomous Claude sessions. Each task has a cron expression, an enabled flag, and a reference to a SKILL.md file that defines what Claude does when the task runs.

---

### 🟢 Active Scheduled Task

- **What**: For each task in `scheduled-tasks.json` where `enabled` is `true`, CLAUDIT generates a finding including the task name (from the associated SKILL.md frontmatter), the task ID, the cron expression, and a human-readable English translation of the schedule (e.g., "Daily at 9:00 AM").
- **Why it matters**:
  - 🔴 **Risk**: Active scheduled tasks are the highest-autonomy feature in Claude Desktop. They run without user interaction on a fixed schedule. Each active task is an autonomous AI agent executing with the user's permissions, connected to whatever services and tools are configured. The cron schedule determines frequency — a task running every minute poses more risk than one running weekly.
  - 📜 **Compliance**: Autonomous AI task execution is a critical audit point. Compliance frameworks increasingly require documentation and governance of autonomous AI agents, including what they do, when they run, and what resources they access.
  - 🤖 **AI enablement**: Scheduled tasks are the culmination of Cowork's agentic capabilities. Each active task represents a fully autonomous workflow.
- **Severity**: ⚠️ `WARN` — Every active scheduled task should be intentionally configured and regularly reviewed.
- **Recommendation**: Review each active task's SKILL.md file to understand what the task does. Verify the cron schedule is appropriate. Disable tasks that are no longer needed. Pay special attention to high-frequency schedules (every minute, every 5 minutes) and tasks with broad tool access.

---

### ⏸️ Disabled Scheduled Tasks

- **What**: Tasks where `enabled` is `false` are listed in the report but do **not** generate a finding.
- **Why it matters**:
  - 🔍 **Visibility**: Disabled tasks still have their SKILL.md files and configuration on disk. They could be re-enabled at any time. Their existence shows what autonomous workflows have been configured in the past.
- **Severity**: **Displayed only** — no finding for disabled tasks.
- **Recommendation**: Clean up disabled tasks that are no longer needed. Review their skills to understand the user's autonomous workflow history.

---

## 12. ⚙️ App Config (config.json)

**Source file:** `~/Library/Application Support/Claude/config.json`

The app config contains application-level settings including OAuth tokens, network mode, extension governance controls, and device identifiers.

---

### 🔑 OAuth Token Storage (Not Checked)

- **What**: `config.json` may contain the key `oauth:tokenCache`. CLAUDIT previously flagged this as a plaintext credential storage issue. **This check has been removed** because the value is encrypted using Electron's [`safeStorage`](https://www.electronjs.org/docs/latest/api/safe-storage) API — it is not stored in plaintext.
- **Why it was removed**: The `oauth:tokenCache` value is prefixed with `v10` (base64: `djEw`), which is the Electron safeStorage version marker. On macOS, safeStorage encrypts data using an AES key stored in the system Keychain, protected by Claude Desktop's code signature. Only the same application running as the same user can decrypt it. This is the standard credential storage approach used by all major Electron apps (VS Code, Slack, Discord, etc.) and is not a security finding.
- **Severity**: None — no finding is generated. The key is still redacted in JSON output as a defence-in-depth measure.
- **Recommendation**: No action required.

---

### 🌐 Network Mode and Device ID

- **What**: Reads `coworkNetworkMode` (e.g., proxy settings, restricted mode) and `ant-did` (Anthropic device identifier) from `config.json`.
- **Why it matters**:
  - 🔍 **Visibility**: Network mode shows whether Claude is operating in a restricted network environment. The device ID is useful for correlating audit results with Anthropic's backend logs.
- **Severity**: **Displayed in the report** — no finding generated for these values.
- **Recommendation**: Verify network mode matches organizational expectations. The device ID is informational.

---

## 13. 💻 Claude Code Settings

**Source file:** `~/.claude/settings.json`

Claude Code is the CLI-based Claude interface. Its settings file contains permission grants that control what Claude Code is allowed to do.

---

### 🔐 Permissions Granted

- **What**: Reads `permissions.allow` from `settings.json` and reports the full list of granted permissions as a comma-separated string (e.g., `"Bash(npm run *)", "Read(~/*)", "Write(~/Projects/*)"` etc.).
- **Why it matters**:
  - 🔴 **Risk**: Permission grants define exactly what Claude Code can do on the system. Broad permissions like `Bash(*)` (run any command) or `Write(/*)` (write anywhere) give Claude Code nearly unrestricted system access. Even narrower grants should be reviewed — each permission is an explicit trust delegation to an AI tool.
  - 📜 **Compliance**: Claude Code permission grants are analogous to IAM policies. They should be reviewed as part of least-privilege assessments. Overly broad grants should be narrowed.
  - 🤖 **AI enablement**: The permission list defines the boundary of what Claude Code can do. It is the primary security control for Claude Code.
- **Severity**: ℹ️ `INFO` — The presence of permissions is expected for Claude Code users. The finding surfaces the list for review.
- **Recommendation**: Review each permission grant for necessity. Apply the principle of least privilege — use specific patterns rather than wildcards. Remove permissions that are no longer needed. Note: CLAUDIT does not currently audit `settings.local.json` which may contain additional permission grants.

---

## 14. 🏃 Runtime State

**Source:** System commands (`pgrep`, `pmset`, `crontab`, filesystem)

Runtime checks examine the live state of the system to detect Claude-related processes, power management overrides, scheduled system tasks, and persistent agents.

---

### 🟢 Claude Processes Running

- **What**: Uses `pgrep -fl Claude` to find running processes with "Claude" in their name or command line. Reports the process count.
- **Why it matters**:
  - 🔍 **Visibility**: Knowing whether Claude is currently running helps contextualize other findings. Active processes indicate Claude is in use. Combined with scheduled tasks and keepAwakeEnabled, this shows whether autonomous operations are actively running.
  - 🤖 **AI enablement**: Process presence indicates active Claude usage.
- **Severity**: ℹ️ `INFO` — Informational; Claude running is expected behavior for users with it installed.
- **Recommendation**: No action required unless Claude should not be running on this machine.

---

### 😴 Sleep Prevention Assertion by Claude/Electron

- **What**: Uses `pmset -g assertions` to list all active macOS power management assertions. Filters for lines containing "Claude" or "Electron" (Claude Desktop is an Electron app). Each matching assertion is reported.
- **Why it matters**:
  - 🔴 **Risk**: Power management assertions prevent macOS from sleeping, keeping the machine continuously active. This overrides organizational power management policies and increases the time window during which the machine is vulnerable to network-based attacks.
  - 📜 **Compliance**: Sleep/lock policies are a common CIS and NIST control. An app actively preventing sleep undermines these controls.
  - 🤖 **AI enablement**: Sleep prevention is typically caused by long-running Cowork sessions or the keepAwakeEnabled preference. Its presence confirms autonomous operation is actively occurring.
- **Severity**: ⚠️ `WARN` — Active sleep prevention is a system-level behavior override that merits review.
- **Recommendation**: If keepAwakeEnabled is off but sleep assertions are present, investigate why Claude is preventing sleep. Check for long-running tasks or background sessions.

---

### 📋 Claude-Related Crontab Entry

- **What**: Reads the user's crontab (`crontab -l`, or `crontab -l -u <user>` when running as root). Filters for lines containing "claude" (case-insensitive). Each matching entry is reported.
- **Why it matters**:
  - 🔴 **Risk**: A crontab entry referencing Claude could indicate an external automation that launches or controls Claude outside of the normal application flow. This could be a legitimate scheduled workflow or evidence of unauthorized automation.
  - 📜 **Compliance**: System-level scheduled tasks should be inventoried and approved.
  - 🤖 **AI enablement**: External cron jobs that invoke Claude represent automation outside of Cowork's built-in scheduling — a different (and potentially less governed) control plane.
- **Severity**: ⚠️ `WARN` — External Claude automation should be reviewed.
- **Recommendation**: Review the crontab entry to understand what it does. If it is a legitimate automation, document it. If unexpected, investigate its origin.

---

### 🚀 Claude LaunchAgent(s) Found

- **What**: Scans `~/Library/LaunchAgents/` for plist files with "claude" in the filename (case-insensitive). Reports the names of any matching plist files.
- **Why it matters**:
  - 🔴 **Risk**: LaunchAgents are macOS persistence mechanisms that start processes at login. A Claude LaunchAgent could ensure Claude runs automatically when the user logs in, enabling autonomous operation from system startup. While the official Claude Desktop installer may create a LaunchAgent, unexpected plists could indicate unauthorized persistence.
  - 📜 **Compliance**: Persistence mechanisms should be inventoried. Unexpected LaunchAgents are a common indicator of malware or unauthorized software.
  - 🤖 **AI enablement**: LaunchAgents that start Claude automatically ensure continuous availability of AI capabilities.
- **Severity**: ⚠️ `WARN` — Persistence mechanisms should be reviewed and verified as legitimate.
- **Recommendation**: Verify each LaunchAgent is from the official Claude Desktop installation. Remove any unexpected plists. Review the plist contents to understand what they launch and with what arguments.

---

### 📁 Large Debug Directory

- **What**: Checks the size of `~/Library/Application Support/Claude/debug/` directory. If the directory exceeds 100 MB, this finding is generated with the actual size.
- **Why it matters**:
  - 🔴 **Risk**: A large debug directory may contain extensive log data including conversation history, tool invocations, API calls, and error details. This data could contain sensitive information and represents a data retention risk.
  - 📜 **Compliance**: Log data retention should be managed according to organizational data retention policies. Excessive debug logs may contain PII or sensitive business data.
  - 🤖 **AI enablement**: Debug data is generated during Claude operation and can be useful for troubleshooting but should be cleaned up regularly.
- **Severity**: ⚠️ `WARN` — Large debug directories indicate excessive data retention.
- **Recommendation**: Review and clean up the debug directory. Consider configuring log rotation or periodic cleanup. Check if debug logging is enabled unnecessarily.

---

## 15. 🍪 Cookies

**Source files:** `~/Library/Application Support/Claude/Cookies`, `~/Library/Application Support/Claude/Cookies-journal`

Claude Desktop (as an Electron app) maintains browser-like cookie storage.

---

### 🍪 Cookie File Presence

- **What**: Checks for the existence of `Cookies` and `Cookies-journal` files. Reports whether each file is present.
- **Why it matters**:
  - 🔍 **Visibility**: Cookie files are a normal byproduct of Electron apps. Their presence indicates Claude Desktop has been used and has active session data on disk.
  - 🤖 **AI enablement**: Cookie file presence is expected for users who have signed into Claude Desktop.
- **Severity**: **Displayed in the report** — no finding generated. Cookie presence is shown for asset inventory purposes.
- **Recommendation**: No action required. Cookie files are expected artifacts of Claude Desktop.

---

## 16. 📊 Severity Level Reference

CLAUDIT uses five severity levels. Here is what each means and when it is applied:

| Emoji | Level | Meaning | Used When |
|-------|-------|---------|-----------|
| ⚠️ | `WARN` | Security-relevant finding requiring review | Autonomous capabilities enabled, unsigned extensions, dangerous tools, governance controls missing, runtime anomalies |
| 🔍 | `REVIEW` | Notable item requiring human assessment | Org-deployed remote plugins (expected but should be verified) |
| ℹ️ | `INFO` | Informational — no action required | Processes running, permissions granted, connectors authenticated, read errors, missing directories |

---

## 📝 Summary of All Findings

Here is a complete catalog of every `add_finding` call in CLAUDIT, organized by severity:

### ⚠️ WARN Findings

| # | Section | Finding | Trigger |
|---|---------|---------|---------|
| 1 | Desktop Settings | keepAwakeEnabled is ON | `preferences.keepAwakeEnabled == true` |
| 2 | Cowork Settings | Scheduled tasks ENABLED | `preferences.coworkScheduledTasksEnabled == true` |
| 3 | Cowork Settings | Code Desktop scheduled tasks ENABLED | `preferences.ccdScheduledTasksEnabled == true` |
| 4 | Cowork Settings | Web search ENABLED | `preferences.coworkWebSearchEnabled == true` |
| 5 | Cowork Settings | Allow all browser actions ENABLED | `preferences.allowAllBrowserActions == true` |
| 6 | Security | Cowork VM egress is UNRESTRICTED | `egressAllowedDomains == ["*"]` in any `local_*.json` session file |
| 7 | Security | Plugin hooks executing commands | 1 or more `hooks/hooks.json` files found with command-type hooks |
| 8 | Security | Extension allowlist DISABLED | Any `dxt:allowlistEnabled` key set to `"false"` in `config.json` |
| 9 | Security | Extension blocklist is empty | `extensions-blocklist.json` exists but has 0 entries |
| 10 | Extensions | Unsigned extension | Extension with `signatureInfo.status == "unsigned"` |
| 11 | Extensions | Extension has dangerous tools | Extension declares `execute_javascript`, `write_file`, `edit_file`, `run_command`, or `execute_sql` |
| 12 | Scheduled Tasks | Active scheduled task | Any task in `scheduled-tasks.json` with `enabled == true` |
| 13 | Runtime | Sleep prevention assertion by Claude/Electron | `pmset -g assertions` output contains "Claude" or "Electron" |
| 14 | Runtime | Claude-related crontab entry | User's `crontab -l` output contains "claude" (case-insensitive) |
| 15 | Runtime | Claude LaunchAgent(s) found | Plist file in `~/Library/LaunchAgents/` containing "claude" in filename |
| 16 | Runtime | Debug directory is large | `~/Library/Application Support/Claude/debug/` exceeds 100 MB |

### 🔍 REVIEW Findings

| # | Section | Finding | Trigger |
|---|---------|---------|---------|
| 1 | Plugins | Remote plugin deployed | Each plugin found in `remote_cowork_plugins/manifest.json` |

### ℹ️ INFO Findings

| # | Section | Finding | Trigger |
|---|---------|---------|---------|
| 1 | Cowork Settings | Cowork VM egress restricted to specific domains | `egressAllowedDomains` is a non-`["*"]` domain list |
| 2 | Cowork Settings | MCP tool(s) explicitly disabled | `enabledMcpTools` contains entries set to `false` |
| 3 | Connectors | Web connectors authenticated | 1 or more web connectors found with active OAuth connections |
| 4 | Claude Code | Permissions granted | `permissions.allow` array is non-empty in `~/.claude/settings.json` |
| 5 | Runtime | Claude is running | `pgrep -fl Claude` returns results |

---

## 🔄 Data Not Generating Findings (Inventory Only)

The following data is collected and displayed in the report but does **not** generate findings. It serves as an asset inventory:

| Section | Data | Purpose |
|---------|------|---------|
| Desktop Settings | menuBarEnabled, sidebarMode, quickEntryShortcut | UX configuration context |
| Cowork Settings | Enabled plugins, extra marketplaces, network mode, egress domain list (when restricted) | Plugin ecosystem and network inventory |
| MCP Servers | Full server table (name, command, args, env vars) | Tool execution inventory |
| Extensions | Full extension table (name, version, author, tools) | Extension inventory |
| Extension Settings | Allowed directories per extension | Filesystem access scope |
| Plugins | Installed plugins, cached plugins, marketplace availability | Plugin inventory |
| Plugin Hooks | Full hook table (plugin, event, command) | Hook execution inventory |
| Connectors | Desktop connectors, not-connected connectors | Integration inventory |
| Skills | User skills, plugin skills (name, description, path) | Behavior/prompt inventory |
| Scheduled Tasks | Disabled tasks | Historical workflow inventory |
| App Config | Network mode, device ID (ant-did) | Configuration context |
| Disabled MCP Tools | Per-session disabled tool list with dangerous tool callout | Tool restriction inventory |
| Cookies | Cookie file presence | Artifact inventory |

---

## 🏷️ Recommendations Engine

CLAUDIT also builds a **Recommendations** list at the end of the report. Recommendations are derived from findings and data but are presented as actionable summaries. They are generated when:

1. ⚡ Keep Awake is ON
2. ⏰ Active scheduled tasks exist
3. ✍️ Unsigned extensions are installed
4. ⚠️ Extensions have dangerous tools
5. 🔌 MCP servers are configured
6. 🔓 Extension allowlist is disabled
7. 🌐 Web search is enabled
8. 🌍 Allow all browser actions is enabled
9. 🚪 Cowork VM network egress is unrestricted
10. 🪝 Plugin hooks execute commands on lifecycle events
11. 📡 Remote plugins are deployed
12. 📦 Cached (not installed) plugins exist
13. 🔐 Web connectors are authenticated

---

*This document was generated for CLAUDIT-SEC v2.2.0. Last updated: 2026-03-19.*
