#Requires -Version 5.1
<#
.SYNOPSIS
    CLAUDIT-SEC - Claude Desktop & Claude Code Security Audit Tool (Windows/PowerShell)
.DESCRIPTION
    Read-only security audit for Windows. Inspects Claude Desktop and Claude Code
    configuration, scheduled tasks, extensions, plugins, skills, permissions, and runtime state.
.NOTES
    PowerShell port of the macOS zsh audit script. No external dependencies required.
#>

param(
    [switch]$Json,
    [string]$User,
    [switch]$AllUsers,
    [Alias('q')]
    [switch]$Quiet,
    [switch]$Version,
    [Alias('h')]
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$_Remaining
)

# Also support --html, --json etc. via manual parsing for scripts invoked with & or .
# The param() block above handles native PowerShell parameter binding.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# Ensure UTF-8 output for Unicode box-drawing and block characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# ── Constants ────────────────────────────────────────────────────────────────

$script:ScriptVersion = "1.0.0"

# Relative path fragments (joined with user-specific roots at runtime)
$script:CLAUDE_DESKTOP_DIR = "Claude"          # relative to $env:APPDATA
$script:CLAUDE_CODE_DIR    = ".claude"          # relative to $env:USERPROFILE

$script:DANGEROUS_TOOLS = @(
    "execute_javascript"
    "write_file"
    "edit_file"
    "run_command"
    "execute_sql"
)

$script:DAY_NAMES = @(
    "Sunday", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday"
)

# Username validation regex
$script:VALID_USER_RE = '^[a-zA-Z0-9._-]+$'

# ── Global State ─────────────────────────────────────────────────────────────

$script:Timestamp    = ""
$script:HostnameVal = ""
$script:AuditUser   = ""
$script:HomeDir     = ""

# Findings (parallel lists)
$script:FindingSev  = [System.Collections.Generic.List[string]]::new()
$script:FindingSect = [System.Collections.Generic.List[string]]::new()
$script:FindingMsg  = [System.Collections.Generic.List[string]]::new()
$script:FindingDet  = [System.Collections.Generic.List[string]]::new()

# Desktop / Cowork prefs
$script:DesktopPrefs  = [ordered]@{}
$script:CoworkPrefs   = [ordered]@{}
$script:AppConfig     = [ordered]@{}
$script:RuntimeInfo   = [ordered]@{}
$script:ExtSettingsJson     = [ordered]@{}   # ext_name -> parsed PSCustomObject
$script:CoworkMarketplacesJson = [ordered]@{} # name -> json string
$script:CoworkEnabledPlugins = [System.Collections.Generic.List[string]]::new()
$script:CoworkNetworkMode   = ""

# MCP Servers
$script:McpNames    = [System.Collections.Generic.List[string]]::new()
$script:McpCmds     = [System.Collections.Generic.List[string]]::new()
$script:McpArgsStr = [System.Collections.Generic.List[string]]::new()
$script:McpEnvKeys = [System.Collections.Generic.List[string]]::new()

# Plugins
$script:PlgNames         = [System.Collections.Generic.List[string]]::new()
$script:PlgVers          = [System.Collections.Generic.List[string]]::new()
$script:PlgSrcs          = [System.Collections.Generic.List[string]]::new()
$script:PlgScopes        = [System.Collections.Generic.List[string]]::new()
$script:PlgAuthors       = [System.Collections.Generic.List[string]]::new()
$script:PlgDescs         = [System.Collections.Generic.List[string]]::new()
$script:PlgMps           = [System.Collections.Generic.List[string]]::new()
$script:PlgInstalledAts = [System.Collections.Generic.List[string]]::new()
$script:PlgSkillCounts  = [System.Collections.Generic.List[string]]::new()
$script:MarketplaceAvailable = [System.Collections.Generic.List[string]]::new()

# Connectors
$script:ConnNames = [System.Collections.Generic.List[string]]::new()
$script:ConnCats  = [System.Collections.Generic.List[string]]::new()
$script:ConnTools = [System.Collections.Generic.List[string]]::new()
$script:ConnTags  = [System.Collections.Generic.List[string]]::new()

# Egress & Session Security
$script:EgressDomains      = ""
$script:EgressUnrestricted = $false
$script:DisabledMcpTools  = [System.Collections.Generic.List[string]]::new()

# Dispatch (mobile-to-desktop task assignment)
$script:DispatchSessionCount  = 0
$script:DispatchActive         = $false
$script:DispatchBridgeEnabled   = $false
$script:DispatchBridgeConsented = $false

# Workspaces (user UUIDs under org)
$script:WsUuids              = [System.Collections.Generic.List[string]]::new()
$script:WsAcctNames         = [System.Collections.Generic.List[string]]::new()
$script:WsEmails             = [System.Collections.Generic.List[string]]::new()
$script:WsSessionCounts     = [System.Collections.Generic.List[string]]::new()
$script:WsDxtAllowlists     = [System.Collections.Generic.List[string]]::new()
$script:WsHasRemotePlugins = [System.Collections.Generic.List[string]]::new()
$script:WsBridgeActive      = [System.Collections.Generic.List[string]]::new()
$script:WsOrgUuid           = ""

# Plugin hooks
$script:HookPlugins = [System.Collections.Generic.List[string]]::new()
$script:HookEvents  = [System.Collections.Generic.List[string]]::new()
$script:HookCmds    = [System.Collections.Generic.List[string]]::new()

# Skills
$script:SkNames   = [System.Collections.Generic.List[string]]::new()
$script:SkDescs   = [System.Collections.Generic.List[string]]::new()
$script:SkSrcs    = [System.Collections.Generic.List[string]]::new()
$script:SkPlugins = [System.Collections.Generic.List[string]]::new()
$script:SkPaths   = [System.Collections.Generic.List[string]]::new()

# Scheduled Tasks
$script:StIds      = [System.Collections.Generic.List[string]]::new()
$script:StCrons    = [System.Collections.Generic.List[string]]::new()
$script:StCronEng = [System.Collections.Generic.List[string]]::new()
$script:StEnableds = [System.Collections.Generic.List[string]]::new()
$script:StFPaths   = [System.Collections.Generic.List[string]]::new()
$script:StSNames   = [System.Collections.Generic.List[string]]::new()
$script:StSDescs   = [System.Collections.Generic.List[string]]::new()
$script:StPrompts  = [System.Collections.Generic.List[string]]::new()

# Extensions (DXT)
$script:ExtIds        = [System.Collections.Generic.List[string]]::new()
$script:ExtNames      = [System.Collections.Generic.List[string]]::new()
$script:ExtVers       = [System.Collections.Generic.List[string]]::new()
$script:ExtAuthors    = [System.Collections.Generic.List[string]]::new()
$script:ExtSigneds    = [System.Collections.Generic.List[string]]::new()
$script:ExtSigStats  = [System.Collections.Generic.List[string]]::new()
$script:ExtToolsStr  = [System.Collections.Generic.List[string]]::new()
$script:ExtDangerStr = [System.Collections.Generic.List[string]]::new()

# Blocklist / Code settings
$script:BlocklistEntries = 0
$script:BlocklistStatus  = ""
$script:ClaudeCodeJson  = $null

# Claude Code Managed Policy (Windows admin-deployed policy + MCP)
# Sources: %PROGRAMFILES%\ClaudeCode (current, v2.1.75+) and %PROGRAMDATA%\ClaudeCode (legacy)
$script:ManagedPolicyFiles      = [System.Collections.Generic.List[string]]::new()  # absolute paths read
$script:ManagedPolicyLegacy     = [System.Collections.Generic.List[string]]::new()  # legacy %PROGRAMDATA% paths read
$script:ManagedMcpNames         = [System.Collections.Generic.List[string]]::new()
$script:ManagedMcpCmds          = [System.Collections.Generic.List[string]]::new()
$script:ManagedMcpArgsStr       = [System.Collections.Generic.List[string]]::new()
$script:ManagedMcpEnvKeys       = [System.Collections.Generic.List[string]]::new()
$script:ManagedMcpSources       = [System.Collections.Generic.List[string]]::new()  # 'programfiles' | 'programdata'
$script:ManagedSettingsKeys     = [System.Collections.Generic.List[string]]::new()  # top-level keys observed
$script:ManagedSettingsLegacyHit = $false                                            # any file found in legacy path

# Skill frontmatter parse results (set by Parse-SkillFrontmatter)
$script:SkillFmName = ""
$script:SkillFmDesc = ""

# Recommendations
$script:Recommendations = [System.Collections.Generic.List[string]]::new()

# Counters
$script:WarnCount = 0
$script:InfoCount = 0

# Session dirs found
$script:SessionDirs = [System.Collections.Generic.List[string]]::new()

# ── CLI: Version / Help (early exit) ────────────────────────────────────────

if ($Version) {
    Write-Output "CLAUDIT-SEC v$script:ScriptVersion"
    exit 0
}

if ($Help) {
    Write-Output "CLAUDIT-SEC v$script:ScriptVersion - Claude Security Audit (Windows)"
    Write-Output "Usage: .\claude_audit.ps1 [-Html [FILE]] [-Json] [-User USER] [-AllUsers] [-Quiet] [-Version] [-Help]"
    Write-Output ""
    Write-Output "Options:"
    Write-Output "  -Html [FILE]    HTML report (auto-named if no FILE given)"
    Write-Output "  -Json           JSON output for SIEM ingestion"
    Write-Output "  -User USER      Scan specific user"
    Write-Output "  -AllUsers       Scan all users with Claude data"
    Write-Output "  -Quiet (-q)     Only show WARN/CRITICAL findings"
    Write-Output "  -Version        Print version and exit"
    Write-Output "  -Help (-h)      Show usage"
    exit 0
}

# Parse -Html / --html [FILE] from remaining args (supports optional value in -File mode)
$script:OptHtml = ""
if ($_Remaining) {
    for ($i = 0; $i -lt $_Remaining.Count; $i++) {
        if ($_Remaining[$i] -match '^-{1,2}[Hh]tml$') {
            if ($i + 1 -lt $_Remaining.Count -and $_Remaining[$i + 1] -notmatch '^-') {
                $script:OptHtml = $_Remaining[$i + 1]
            }
            else {
                $script:OptHtml = "AUTO"
            }
            break
        }
    }
}

# Mutual exclusion check
if ($User -and $AllUsers) {
    Write-Error "Error: -User and -AllUsers are mutually exclusive"
    exit 1
}

# Map to script-scope option variables used by the rest of the script
$script:OptJson      = [bool]$Json
$script:OptUser      = $User
$script:OptAllUsers = [bool]$AllUsers
$script:OptQuiet     = [bool]$Quiet

# ── Preflight ────────────────────────────────────────────────────────────────

# No jq dependency needed - PowerShell has ConvertFrom-Json built-in.
# No OS check needed - this script is Windows-native PowerShell.
# Minimum PowerShell version is enforced by #Requires -Version 5.1 above.

# ── Utility Functions ────────────────────────────────────────────────────────

function Add-Finding {
    <#
    .SYNOPSIS
        Appends a finding to the global findings arrays.
    #>
    param(
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Message,
        [string]$Detail = ""
    )
    $script:FindingSev.Add($Severity)
    $script:FindingSect.Add($Section)
    $script:FindingMsg.Add($Message)
    $script:FindingDet.Add($Detail)
}

function Get-JsonProp {
    <#
    .SYNOPSIS
        Safely reads a property from a PSCustomObject with a default fallback.
    #>
    param([PSCustomObject]$Obj, [string]$Name, [string]$Default = '')
    if ($Obj -and $Obj.PSObject.Properties[$Name]) { return "$($Obj.$Name)" }
    return $Default
}

function Get-AuthorName {
    <#
    .SYNOPSIS
        Extracts author name from a PSCustomObject, handling both string and object author fields.
    #>
    param([PSCustomObject]$Obj)
    if (-not $Obj -or -not $Obj.PSObject.Properties['author']) { return '' }
    if ($Obj.author -is [PSCustomObject] -and $Obj.author.PSObject.Properties['name']) {
        return "$($Obj.author.name)"
    }
    return "$($Obj.author)"
}


function ConvertTo-HtmlEscaped {
    <#
    .SYNOPSIS
        Escapes a string for safe embedding in HTML content.
    #>
    param([string]$s)
    if ($null -eq $s) { return "" }
    $s = $s.Replace('&', '&amp;')
    $s = $s.Replace('<', '&lt;')
    $s = $s.Replace('>', '&gt;')
    $s = $s.Replace('"', '&quot;')
    $s = $s.Replace("'", '&#39;')
    return $s
}

function Get-TruncatedString {
    <#
    .SYNOPSIS
        Truncates a string to maxLen characters, appending "..." if truncated.
    #>
    param(
        [string]$s,
        [int]$maxLen
    )
    if ($null -eq $s) { return "" }
    if ($s.Length -le $maxLen) { return $s }
    return $s.Substring(0, $maxLen - 3) + "..."
}

function Read-SafeJson {
    <#
    .SYNOPSIS
        Reads and parses a JSON file safely. Returns parsed object or $null.
        Sets $script:JsonError to indicate failure reason.
    #>
    param([string]$Path)
    $script:JsonError = ""

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $script:JsonError = "ABSENT"
        return $null
    }

    $fileInfo = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($fileInfo -and $fileInfo.Length -gt 10MB) {
        $script:JsonError = "FILE_TOO_LARGE"
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match 'Access.*denied|UnauthorizedAccess') {
            $script:JsonError = "PERMISSION_DENIED"
        } else {
            $script:JsonError = "READ_ERROR"
        }
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        # Empty file - return empty object equivalent
        return [PSCustomObject]@{}
    }

    try {
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        return $parsed
    }
    catch {
        $script:JsonError = "MALFORMED_JSON"
        return $null
    }
}


function Format-Bytes {
    <#
    .SYNOPSIS
        Formats a byte count into a human-readable string.
    #>
    param([long]$n)
    if ($n -lt 1024)       { return "$n B" }
    if ($n -lt 1048576)    { return "{0:N1} KB" -f ($n / 1024) }
    if ($n -lt 1073741824) { return "{0:N1} MB" -f ($n / 1048576) }
    return "{0:N1} GB" -f ($n / 1073741824)
}

function Parse-SkillFrontmatter {
    <#
    .SYNOPSIS
        Parses YAML frontmatter from a SKILL.md file.
        Returns a hashtable with 'Name' and 'Description' keys.
    #>
    param([string]$File)

    $script:SkillFmName = ""
    $script:SkillFmDesc = ""

    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { return }

    try {
        $content = Get-Content -LiteralPath $File -Raw -ErrorAction Stop
    }
    catch {
        return
    }

    if ([string]::IsNullOrEmpty($content)) { return }
    $result = @{ Name = ""; Description = "" }

    $lines = $content -split "`n"
    if ($lines.Count -eq 0 -or $lines[0].TrimEnd() -notmatch '^---') { return }

    # Extract frontmatter between first --- and second ---
    $fmLines = @()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i].TrimEnd() -match '^---') { break }
        $fmLines += $lines[$i]
    }

    # Parse name
    foreach ($line in $fmLines) {
        if ($line -match '^name:\s*(.+)$') {
            $val = $Matches[1].Trim()
            $val = $val -replace "^[`"']", "" -replace "[`"']$", ""
            $result.Name = $val
            break
        }
    }

    # Parse description (simple single-line or multiline with indentation)
    $inDesc = $false
    $descParts = @()
    foreach ($line in $fmLines) {
        if ($inDesc) {
            if ($line -match '^  (.+)$') {
                $descParts += $Matches[1].Trim()
            } else {
                $inDesc = $false
            }
        }
        elseif ($line -match '^description:\s*(.*)$') {
            $val = $Matches[1].Trim()
            if ($val -eq '' -or $val -eq '>' -or $val -eq '|') {
                # Multiline description follows
                $inDesc = $true
            } else {
                $val = $val -replace "^[`"']", "" -replace "[`"']$", ""
                $result.Description = $val
                break
            }
        }
    }
    if ($descParts.Count -gt 0) {
        $result.Description = $descParts -join " "
    }

    # Set script-scope vars used by collector callers
    $script:SkillFmName = $result.Name
    $script:SkillFmDesc = $result.Description
}

# ── Cron-to-English Parser ───────────────────────────────────────────────────

function Format-CronTime {
    <#
    .SYNOPSIS
        Formats hour and minute into 12-hour AM/PM time string.
    #>
    param([int]$Hour, [int]$Minute)
    $mStr = "{0:D2}" -f $Minute
    if ($Hour -eq 0)       { return "12:$mStr AM" }
    if ($Hour -lt 12)      { return "${Hour}:$mStr AM" }
    if ($Hour -eq 12)      { return "12:$mStr PM" }
    return "$($Hour - 12):$mStr PM"
}

function Format-CronDow {
    <#
    .SYNOPSIS
        Converts a cron day-of-week field to human-readable text.
    #>
    param([string]$Dow)
    if ($Dow -eq '*')   { return "" }
    if ($Dow -eq '1-5') { return "Weekdays" }
    if ($Dow -eq '0-6') { return "" }

    if ($Dow -match '^[0-6]$') {
        return $script:DAY_NAMES[[int]$Dow]
    }

    if ($Dow -match ',') {
        $parts = $Dow -split ','
        $names = @()
        foreach ($p in $parts) {
            if ($p -match '^[0-6]$') {
                $names += $script:DAY_NAMES[[int]$p]
            }
        }
        if ($names.Count -gt 0) { return $names -join ", " }
    }

    return $Dow
}

function ConvertTo-CronEnglish {
    <#
    .SYNOPSIS
        Converts a 5-field cron expression to a human-readable English string.
    #>
    param([string]$Expr)

    $parts = $Expr.Trim() -split '\s+'
    if ($parts.Count -ne 5) { return $Expr }

    $minute = $parts[0]
    $hour   = $parts[1]
    $dom    = $parts[2]
    $month  = $parts[3]
    $dow    = $parts[4]

    # Every minute
    if ($minute -eq '*' -and $hour -eq '*' -and $dom -eq '*' -and $month -eq '*' -and $dow -eq '*') {
        return "Every minute"
    }

    # Every N minutes
    if ($minute -match '^\*/(\d+)$' -and $hour -eq '*' -and $dom -eq '*' -and $month -eq '*' -and $dow -eq '*') {
        $n = [int]$Matches[1]
        if ($n -eq 1) { return "Every minute" }
        return "Every $n minutes"
    }

    # Every N hours (minute=0, hour=*/N)
    if ($minute -eq '0' -and $hour -match '^\*/(\d+)$' -and $dom -eq '*' -and $month -eq '*' -and $dow -eq '*') {
        $n = [int]$Matches[1]
        if ($n -eq 1) { return "Every hour" }
        return "Every $n hours"
    }

    # Every hour on the hour
    if ($minute -eq '0' -and $hour -eq '*' -and $dom -eq '*' -and $month -eq '*' -and $dow -eq '*') {
        return "Every hour"
    }

    # Every hour at :MM
    if ($hour -eq '*' -and $dom -eq '*' -and $month -eq '*' -and $dow -eq '*') {
        if ($minute -match '^\d+$') {
            return "Every hour at :{0:D2}" -f [int]$minute
        }
    }

    # From here we need numeric hour and minute
    if ($minute -notmatch '^\d+$' -or $hour -notmatch '^\d+$') { return $Expr }
    $m = [int]$minute
    $h = [int]$hour
    $timeStr = Format-CronTime -Hour $h -Minute $m

    # Monthly on day N
    if ($dom -ne '*' -and $month -eq '*' -and $dow -eq '*') {
        if ($dom -match '^\d+$') { return "Monthly on day $dom at $timeStr" }
        return $Expr
    }

    # Daily / Weekly
    if ($dom -eq '*' -and $month -eq '*') {
        if ($dow -eq '*')   { return "Daily at $timeStr" }
        if ($dow -eq '1-5') { return "Weekdays at $timeStr" }
        $dayName = Format-CronDow -Dow $dow
        if ($dayName) { return "Weekly on $dayName at $timeStr" }
    }

    return $Expr
}

# ── User Context Detection ───────────────────────────────────────────────────

function Get-UserContexts {
    <#
    .SYNOPSIS
        Determines which user(s) to audit. Returns array of PSCustomObject with
        Username and HomeDir properties.
    #>

    $contexts = @()

    # Explicit --user
    if ($script:OptUser) {
        if ($script:OptUser -notmatch $script:VALID_USER_RE -or $script:OptUser -match '^\.\.*$') {
            Write-Error "Invalid username: '$($script:OptUser)'."
            exit 1
        }
        # Resolve home directory for the specified user
        $profilePath = $null
        try {
            $userObj = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
                Where-Object {
                    -not $_.Special -and
                    $_.LocalPath -and
                    (Split-Path $_.LocalPath -Leaf) -eq $script:OptUser
                } | Select-Object -First 1
            if ($userObj) { $profilePath = $userObj.LocalPath }
        } catch {}

        if (-not $profilePath) {
            # Fallback: assume C:\Users\<username>
            $profilePath = Join-Path "C:\Users" $script:OptUser
        }

        $contexts += [PSCustomObject]@{ Username = $script:OptUser; HomeDir = $profilePath }
        return $contexts
    }

    # --all-users or running as admin
    $isAdmin = $false
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    if ($script:OptAllUsers -or $isAdmin) {
        $script:OptAllUsers = $true

        try {
            $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
                Where-Object {
                    -not $_.Special -and
                    $_.LocalPath -and
                    $_.LocalPath -match '^[A-Z]:\\Users\\'
                }
        } catch {
            $profiles = @()
        }

        foreach ($prof in $profiles) {
            $uname = Split-Path $prof.LocalPath -Leaf
            # Skip system-like accounts
            if ($uname -match '^(defaultuser0|Default|Public|All Users)$') { continue }
            if ($uname -notmatch $script:VALID_USER_RE) { continue }

            $homeDir = $prof.LocalPath
            $appDataDir = Join-Path $homeDir "AppData\Roaming\$($script:CLAUDE_DESKTOP_DIR)"
            $codeDir    = Join-Path $homeDir $script:CLAUDE_CODE_DIR

            if ((Test-Path -LiteralPath $appDataDir -PathType Container) -or
                (Test-Path -LiteralPath $codeDir -PathType Container)) {
                $contexts += [PSCustomObject]@{ Username = $uname; HomeDir = $homeDir }
            }
        }

        if ($contexts.Count -eq 0) {
            Write-Error "No users with Claude data found."
            exit 1
        }
        return $contexts
    }

    # Default: current user
    $curUser = $env:USERNAME
    if (-not $curUser) { $curUser = "unknown" }
    $curHome = $env:USERPROFILE
    if (-not $curHome) { $curHome = "C:\Users\$curUser" }

    $contexts += [PSCustomObject]@{ Username = $curUser; HomeDir = $curHome }
    return $contexts
}

# ── Session Directory Discovery ──────────────────────────────────────────────

function Find-SessionDirs {
    <#
    .SYNOPSIS
        Finds local-agent-mode-sessions/<org>/<user>/ directories under the
        given Claude Desktop directory. Populates $script:SessionDirs.
    #>
    param([string]$ClaudeDir)

    $script:SessionDirs = [System.Collections.Generic.List[string]]::new()
    $sessionsDir = Join-Path $ClaudeDir "local-agent-mode-sessions"

    if (-not (Test-Path -LiteralPath $sessionsDir -PathType Container)) { return }

    foreach ($orgDir in (Get-ChildItem -LiteralPath $sessionsDir -Directory -ErrorAction SilentlyContinue)) {
        if ($orgDir.Name.StartsWith('.') -or $orgDir.Name -eq 'skills-plugin') { continue }

        foreach ($userDir in (Get-ChildItem -LiteralPath $orgDir.FullName -Directory -ErrorAction SilentlyContinue)) {
            if ($userDir.Name.StartsWith('.')) { continue }
            $script:SessionDirs.Add($userDir.FullName)
        }
    }
}

# ── Reset Audit State ───────────────────────────────────────────────────────

function Reset-AuditState {
    <#
    .SYNOPSIS
        Clears all global arrays, hashtables, and counters for a fresh audit run.
        Called before each user scan in multi-user mode.
    #>

    $script:FindingSev.Clear()
    $script:FindingSect.Clear()
    $script:FindingMsg.Clear()
    $script:FindingDet.Clear()

    $script:DesktopPrefs  = [ordered]@{}
    $script:CoworkPrefs   = [ordered]@{}
    $script:AppConfig     = [ordered]@{}
    $script:RuntimeInfo   = [ordered]@{}
    $script:ExtSettingsJson     = [ordered]@{}
    $script:CoworkMarketplacesJson = [ordered]@{}
    $script:CoworkEnabledPlugins.Clear()
    $script:CoworkNetworkMode = ""

    $script:McpNames.Clear()
    $script:McpCmds.Clear()
    $script:McpArgsStr.Clear()
    $script:McpEnvKeys.Clear()

    $script:PlgNames.Clear()
    $script:PlgVers.Clear()
    $script:PlgSrcs.Clear()
    $script:PlgScopes.Clear()
    $script:PlgAuthors.Clear()
    $script:PlgDescs.Clear()
    $script:PlgMps.Clear()
    $script:PlgInstalledAts.Clear()
    $script:PlgSkillCounts.Clear()
    $script:MarketplaceAvailable.Clear()

    $script:ConnNames.Clear()
    $script:ConnCats.Clear()
    $script:ConnTools.Clear()
    $script:ConnTags.Clear()

    $script:EgressDomains      = ""
    $script:EgressUnrestricted = $false
    $script:DisabledMcpTools.Clear()

    $script:DispatchSessionCount  = 0
    $script:DispatchActive         = $false
    $script:DispatchBridgeEnabled   = $false
    $script:DispatchBridgeConsented = $false

    $script:WsUuids.Clear()
    $script:WsAcctNames.Clear()
    $script:WsEmails.Clear()
    $script:WsSessionCounts.Clear()
    $script:WsDxtAllowlists.Clear()
    $script:WsHasRemotePlugins.Clear()
    $script:WsBridgeActive.Clear()
    $script:WsOrgUuid = ""

    $script:HookPlugins.Clear()
    $script:HookEvents.Clear()
    $script:HookCmds.Clear()

    $script:SkNames.Clear()
    $script:SkDescs.Clear()
    $script:SkSrcs.Clear()
    $script:SkPlugins.Clear()
    $script:SkPaths.Clear()

    $script:StIds.Clear()
    $script:StCrons.Clear()
    $script:StCronEng.Clear()
    $script:StEnableds.Clear()
    $script:StFPaths.Clear()
    $script:StSNames.Clear()
    $script:StSDescs.Clear()
    $script:StPrompts.Clear()

    $script:ExtIds.Clear()
    $script:ExtNames.Clear()
    $script:ExtVers.Clear()
    $script:ExtAuthors.Clear()
    $script:ExtSigneds.Clear()
    $script:ExtSigStats.Clear()
    $script:ExtToolsStr.Clear()
    $script:ExtDangerStr.Clear()

    $script:BlocklistEntries = 0
    $script:BlocklistStatus  = ""
    $script:ClaudeCodeJson  = $null

    $script:ManagedPolicyFiles.Clear()
    $script:ManagedPolicyLegacy.Clear()
    $script:ManagedMcpNames.Clear()
    $script:ManagedMcpCmds.Clear()
    $script:ManagedMcpArgsStr.Clear()
    $script:ManagedMcpEnvKeys.Clear()
    $script:ManagedMcpSources.Clear()
    $script:ManagedSettingsKeys.Clear()
    $script:ManagedSettingsLegacyHit = $false

    $script:Recommendations.Clear()

    $script:WarnCount = 0
    $script:InfoCount = 0

    $script:SessionDirs.Clear()
}


# ── Redaction Helper ────────────────────────────────────────────────────────

# Regex for redacting sensitive args/values
$script:REDACT_PATTERN = '(?i)(sk-|[_\-]?key[_=\-]|[_\-]?token[_=\-]|[_\-]?secret[_=\-]|[_\-]?password[_=\-]|Password=|[_\-]?passwd[_=\-]|[_\-]?auth[_=\-]|[_\-]?credentials?[_=\-]|[_\-]?api[_\-]?key|://[^@]+@|ghp_[a-zA-Z0-9]|gho_|github_pat_|xox[bpras]-|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_\-]{20,}\.ey|bearer\s+\S{10,})'

function Redact-Arg {
    param([string]$Value)
    if ($Value -match $script:REDACT_PATTERN) { return '[REDACTED]' }
    return $Value
}

# ── Data Collectors ─────────────────────────────────────────────────────────

# ============================================================================
# 1. Collect-DesktopSettings
# ============================================================================
function Collect-DesktopSettings {
    param([string]$ClaudeDir)
    $configPath = Join-Path $ClaudeDir 'claude_desktop_config.json'
    $data = Read-SafeJson $configPath
    if ($script:JsonError) {
        Add-Finding 'INFO' 'Desktop Settings' "claude_desktop_config.json: [$($script:JsonError)]"
        return
    }
    if (-not $data) { return }

    # Preferences
    $prefs = $null
    if ($data.PSObject.Properties['preferences']) { $prefs = $data.preferences }
    if (-not $prefs) { $prefs = [PSCustomObject]@{} }

    $script:DesktopPrefs['keepAwakeEnabled']   = Get-JsonProp $prefs 'keepAwakeEnabled' 'false'
    $script:DesktopPrefs['menuBarEnabled']      = Get-JsonProp $prefs 'menuBarEnabled' 'false'
    $script:DesktopPrefs['sidebarMode']         = Get-JsonProp $prefs 'sidebarMode'
    $script:DesktopPrefs['quickEntryShortcut']  = Get-JsonProp $prefs 'quickEntryShortcut'

    if ($script:DesktopPrefs['keepAwakeEnabled'] -eq 'true' -or $script:DesktopPrefs['keepAwakeEnabled'] -eq 'True') {
        Add-Finding 'WARN' 'Desktop Settings' 'keepAwakeEnabled is ON - prevents Windows from sleeping' 'keepAwakeEnabled=true'
    }

    # Cowork prefs from desktop config preferences
    $script:CoworkPrefs['coworkScheduledTasksEnabled'] = Get-JsonProp $prefs 'coworkScheduledTasksEnabled' 'false'
    $script:CoworkPrefs['ccdScheduledTasksEnabled']    = Get-JsonProp $prefs 'ccdScheduledTasksEnabled' 'false'
    $script:CoworkPrefs['coworkWebSearchEnabled']      = Get-JsonProp $prefs 'coworkWebSearchEnabled' 'false'
    $script:CoworkPrefs['allowAllBrowserActions']       = Get-JsonProp $prefs 'allowAllBrowserActions' 'false'

    # NOTE: Scheduled-tasks-enabled findings are deferred to Collect-ScheduledTasks
    # so we can distinguish "enabled with tasks" (WARN) from "enabled but empty" (INFO).
    if ($script:CoworkPrefs['coworkWebSearchEnabled'] -match '^[Tt]rue$') {
        Add-Finding 'WARN' 'Cowork Settings' 'Web search ENABLED - autonomous internet access' 'coworkWebSearchEnabled=true'
    }
    if ($script:CoworkPrefs['allowAllBrowserActions'] -match '^[Tt]rue$') {
        Add-Finding 'WARN' 'Cowork Settings' 'Allow all browser actions ENABLED - Claude can browse any website without asking' 'allowAllBrowserActions=true'
    }

    # MCP Servers
    $mcpJson = $null
    if ($data.PSObject.Properties['mcpServers']) { $mcpJson = $data.mcpServers }
    if ($mcpJson) {
        $mcpJson.PSObject.Properties | ForEach-Object {
            $sname = $_.Name
            $srv = $_.Value

            $cmd = Get-JsonProp $srv 'command' '[unknown]'

            $argsArr = @()
            if ($srv.PSObject.Properties['args'] -and $srv.args -is [array]) {
                $argsArr = $srv.args | ForEach-Object { Redact-Arg "$_" }
            }
            $argsStr = $argsArr -join ' '

            $envKeys = '-'
            if ($srv.PSObject.Properties['env'] -and $srv.env) {
                $keys = @($srv.env.PSObject.Properties | ForEach-Object { $_.Name })
                if ($keys.Count -gt 0) { $envKeys = $keys -join ', ' }
            }

            $script:McpNames    += $sname
            $script:McpCmds     += $cmd
            $script:McpArgsStr  += $argsStr
            $script:McpEnvKeys  += $envKeys
        }
    }
}

# ============================================================================
# 2. Collect-CoworkSettings
# ============================================================================
function Collect-CoworkSettings {
    foreach ($sessDir in $script:SessionDirs) {
        $csPath = Join-Path $sessDir 'cowork_settings.json'
        $data = Read-SafeJson $csPath
        if ($script:JsonError -or -not $data) { continue }

        # Enabled plugins
        if ($data.PSObject.Properties['enabledPlugins'] -and $data.enabledPlugins) {
            $data.enabledPlugins.PSObject.Properties | ForEach-Object {
                if ("$($_.Value)" -match '^[Tt]rue$') {
                    $script:CoworkEnabledPlugins += $_.Name
                }
            }
        }

        # Extra known marketplaces
        if ($data.PSObject.Properties['extraKnownMarketplaces'] -and $data.extraKnownMarketplaces) {
            $data.extraKnownMarketplaces.PSObject.Properties | ForEach-Object {
                $script:CoworkMarketplacesJson[$_.Name] = $_.Value
            }
        }
    }
}

# ============================================================================
# 3. Collect-AppConfig
# ============================================================================
function Collect-AppConfig {
    param([string]$ClaudeDir)
    $configPath = Join-Path $ClaudeDir 'config.json'
    $data = Read-SafeJson $configPath
    if ($script:JsonError) {
        if ($script:JsonError -ne 'ABSENT') {
            Add-Finding 'INFO' 'App Config' "config.json: [$($script:JsonError)]"
        }
        return
    }
    if (-not $data) { return }

    # Store raw config for workspace detection
    $script:AppConfig['_raw_config'] = $data

    # coworkNetworkMode
    if ($data.PSObject.Properties['coworkNetworkMode'] -and $data.coworkNetworkMode) {
        $nm = "$($data.coworkNetworkMode)"
        $script:CoworkNetworkMode = $nm
        $script:AppConfig['coworkNetworkMode'] = $nm
    }

    # oauth:tokenCache — encrypted via Electron safeStorage (DPAPI on Windows)
    # Standard Electron credential storage, not a security finding

    # DXT allowlist keys
    $data.PSObject.Properties | Where-Object { $_.Name -like '*dxt:allowlistEnabled*' } | ForEach-Object {
        $dk = $_.Name
        $val = "$($_.Value)"
        $script:AppConfig[$dk] = $val
        if ($val -eq 'false' -or $val -eq 'False') {
            Add-Finding 'WARN' 'Security' "Extension allowlist DISABLED: $dk" 'Any extension can be installed without approval'
        }
    }

    # ant-did (device ID)
    if ($data.PSObject.Properties['ant-did'] -and $data.'ant-did') {
        $antDid = "$($data.'ant-did')"
        $script:RuntimeInfo['ant_did'] = $antDid
        $script:AppConfig['ant-did'] = $antDid
    }
}

# ============================================================================
# 4. Collect-Extensions
# ============================================================================
function Collect-Extensions {
    param([string]$ClaudeDir)
    $extPath = Join-Path $ClaudeDir 'extensions-installations.json'
    $data = Read-SafeJson $extPath
    if ($script:JsonError) {
        if ($script:JsonError -ne 'ABSENT') {
            Add-Finding 'INFO' 'Extensions' "extensions-installations.json: [$($script:JsonError)]"
        }
        return
    }
    if (-not $data) { return }

    # Normalize to array
    $extArray = @()
    if ($data.PSObject.Properties['extensions']) {
        $extJson = $data.extensions
    } else {
        $extJson = $data
    }
    if ($extJson -is [array]) {
        $extArray = $extJson
    } elseif ($extJson -is [PSCustomObject]) {
        # Object with values that are extension objects
        $extArray = @($extJson.PSObject.Properties | ForEach-Object { $_.Value } | Where-Object { $_ -is [PSCustomObject] })
    }

    foreach ($e in $extArray) {
        if (-not ($e -is [PSCustomObject])) { continue }
        $eid      = Get-JsonProp $e 'id' 'unknown'
        $eversion = Get-JsonProp $e 'version' '?'

        # Manifest fields
        $manifest = $null
        if ($e.PSObject.Properties['manifest']) { $manifest = $e.manifest }
        $ename  = $eid
        $eauthor = ''
        if ($manifest) {
            $dn = Get-JsonProp $manifest 'display_name'
            if ($dn) { $ename = $dn }
            else {
                $mn = Get-JsonProp $manifest 'name'
                if ($mn) { $ename = $mn }
            }
            $eauthor = Get-AuthorName $manifest
        }

        # Signature
        $esigStatus = 'unsigned'
        $esigned    = 'false'
        if ($e.PSObject.Properties['signatureInfo'] -and $e.signatureInfo -and $e.signatureInfo.PSObject.Properties['status']) {
            $esigStatus = "$($e.signatureInfo.status)"
            if ($esigStatus -ne 'unsigned') { $esigned = 'true' }
        }

        # Tools
        $toolsArr  = @()
        $dangerArr = @()
        if ($manifest -and $manifest.PSObject.Properties['tools'] -and $manifest.tools -is [array]) {
            foreach ($t in $manifest.tools) {
                $tn = ''
                if ($t -is [PSCustomObject] -and $t.PSObject.Properties['name']) { $tn = "$($t.name)" }
                elseif ($t -is [string]) { $tn = $t }
                if ($tn) {
                    $toolsArr += $tn
                    if ($tn -in $script:DANGEROUS_TOOLS) { $dangerArr += $tn }
                }
            }
        }
        $toolsStr  = $toolsArr -join ','
        $dangerStr = $dangerArr -join ','

        $script:ExtIds      += $eid
        $script:ExtNames    += $ename
        $script:ExtVers     += $eversion
        $script:ExtAuthors  += $eauthor
        $script:ExtSigneds  += $esigned
        $script:ExtSigStats += $esigStatus
        $script:ExtToolsStr += $toolsStr
        $script:ExtDangerStr += $dangerStr

        if ($esigned -eq 'false') {
            Add-Finding 'WARN' 'Extensions' "Unsigned extension: $ename" "version=$eversion"
        }
        if ($dangerStr) {
            Add-Finding 'WARN' 'Extensions' "Extension '$ename' has dangerous tools: $($dangerStr -replace ',', ', ')"
        }
    }
}

# ============================================================================
# 5. Collect-ExtensionSettings
# ============================================================================
function Collect-ExtensionSettings {
    param([string]$ClaudeDir)
    $settingsDir = Join-Path $ClaudeDir 'Claude Extensions Settings'
    if (-not (Test-Path -LiteralPath $settingsDir -PathType Container)) { return }
    Get-ChildItem -LiteralPath $settingsDir -Filter '*.json' -File -ErrorAction SilentlyContinue | ForEach-Object {
        $data = Read-SafeJson $_.FullName
        if ($script:JsonError -or -not $data) { return }
        $extName = $_.BaseName
        $script:ExtSettingsJson[$extName] = $data
    }
}

# ============================================================================
# 6. Collect-Plugins
# ============================================================================
function Collect-Plugins {
    $installedNames = @{}
    $remoteNames    = @{}

    foreach ($sessDir in $script:SessionDirs) {
        # a) Installed plugins
        $ipPath = Join-Path $sessDir 'cowork_pluginsinstalled_plugins.json'
        $ipData = Read-SafeJson $ipPath
        if (-not $script:JsonError -and $ipData -and $ipData.PSObject.Properties['plugins'] -and $ipData.plugins) {
            $ipData.plugins.PSObject.Properties | ForEach-Object {
                $pkey = $_.Name
                $namePart = $pkey -replace '@.*$', ''
                $mpPart   = if ($pkey -match '@(.+)$') { $Matches[1] } else { '' }

                $entries = $_.Value
                if ($entries -isnot [array]) { $entries = @($entries) }

                foreach ($entry in $entries) {
                    if (-not ($entry -is [PSCustomObject])) { continue }
                    $pver    = Get-JsonProp $entry 'version' '?'
                    $pscope  = Get-JsonProp $entry 'scope'
                    $pinstAt = Get-JsonProp $entry 'installedAt'
                    $installPath = Get-JsonProp $entry 'installPath'

                    # Validate installPath: must not be UNC and must be under session or Claude data dir
                    $_claudeDir = Join-Path (Join-Path $script:HomeDir "AppData\Roaming") $script:CLAUDE_DESKTOP_DIR
                    $installPathSafe = $false
                    if ($installPath -and -not $installPath.StartsWith('\\') -and
                        ($installPath.StartsWith($sessDir, [StringComparison]::OrdinalIgnoreCase) -or
                         $installPath.StartsWith($_claudeDir, [StringComparison]::OrdinalIgnoreCase))) {
                        $installPathSafe = $true
                    }

                    $pauthor = ''; $pdesc = ''
                    if ($installPath -and $installPathSafe) {
                        $pjPath = Join-Path $installPath '.claude-pluginplugin.json'
                        $pjData = Read-SafeJson $pjPath
                        if (-not $script:JsonError -and $pjData) {
                            $pauthor = Get-AuthorName $pjData
                            $pdesc = Get-JsonProp $pjData 'description'
                        }
                    }

                    $skCount = 0
                    if ($installPath -and $installPathSafe) {
                        $skDir = Join-Path $installPath 'skills'
                        if (Test-Path -LiteralPath $skDir -PathType Container) {
                            $skCount = @(Get-ChildItem -LiteralPath $skDir -Directory -ErrorAction SilentlyContinue).Count
                        }
                    }

                    $script:PlgNames       += $namePart
                    $script:PlgVers        += $pver
                    $script:PlgSrcs        += 'installed'
                    $script:PlgScopes      += $pscope
                    $script:PlgAuthors     += $pauthor
                    $script:PlgDescs       += $pdesc
                    $script:PlgMps         += $mpPart
                    $script:PlgInstalledAts += $pinstAt
                    $script:PlgSkillCounts += $skCount
                    $installedNames[$namePart] = $true
                }
            }
        }

        # b) Remote plugins
        $remoteDir    = Join-Path $sessDir 'remote_cowork_plugins'
        $manifestPath = Join-Path $remoteDir 'manifest.json'
        $manifestData = Read-SafeJson $manifestPath
        if (-not $script:JsonError -and $manifestData -and $manifestData.PSObject.Properties['plugins'] -and $manifestData.plugins -is [array]) {
            foreach ($rp in $manifestData.plugins) {
                if (-not ($rp -is [PSCustomObject])) { continue }
                $rpId   = Get-JsonProp $rp 'id'
                $rpName = Get-JsonProp $rp 'name'
                $rpMp   = Get-JsonProp $rp 'marketplaceName'
                $rpBy   = Get-JsonProp $rp 'installedBy'

                $rpVer = ''; $rpAuthor = ''; $rpDesc = ''
                $rpPjPath = Join-Path (Join-Path $remoteDir $rpId) '.claude-plugin\plugin.json'
                $rpPj = Read-SafeJson $rpPjPath
                if (-not $script:JsonError -and $rpPj) {
                    $rpVer    = Get-JsonProp $rpPj 'version'
                    $rpAuthor = Get-AuthorName $rpPj
                    $rpDesc   = Get-JsonProp $rpPj 'description'
                }

                $rpSk = 0
                $rpSkDir = Join-Path (Join-Path $remoteDir $rpId) 'skills'
                if (Test-Path -LiteralPath $rpSkDir -PathType Container) {
                    $rpSk = @(Get-ChildItem -LiteralPath $rpSkDir -Directory -ErrorAction SilentlyContinue).Count
                }

                $script:PlgNames       += $rpName
                $script:PlgVers        += $rpVer
                $script:PlgSrcs        += 'remote'
                $script:PlgScopes      += ''
                $script:PlgAuthors     += $rpAuthor
                $script:PlgDescs       += $rpDesc
                $script:PlgMps         += $rpMp
                $script:PlgInstalledAts += ''
                $script:PlgSkillCounts += $rpSk
                $remoteNames[$rpName] = $true
                Add-Finding 'REVIEW' 'Plugins' "Remote plugin: $rpName (v$rpVer) deployed by $rpBy" "id=$rpId, marketplace=$rpMp"
            }
        }

        # c) Marketplace catalog (not installed — just track available names)
        $mpBase = Join-Path $sessDir 'cowork_pluginsmarketplaces'
        if (Test-Path -LiteralPath $mpBase -PathType Container) {
            Get-ChildItem -LiteralPath $mpBase -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | ForEach-Object {
                $mpDir = $_.FullName
                Get-ChildItem -LiteralPath $mpDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | ForEach-Object {
                    $pluginDir = $_.FullName
                    $pname = $_.Name
                    $pluginJson = Join-Path $pluginDir '.claude-pluginplugin.json'
                    if (Test-Path -LiteralPath $pluginJson -PathType Leaf) {
                        if (-not $installedNames.ContainsKey($pname) -and -not $remoteNames.ContainsKey($pname)) {
                            $script:MarketplaceAvailable += $pname
                        }
                    } else {
                        # Check subdirectories (version dirs)
                        Get-ChildItem -LiteralPath $pluginDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | ForEach-Object {
                            $subJson = Join-Path $_.FullName '.claude-pluginplugin.json'
                            if (Test-Path -LiteralPath $subJson -PathType Leaf) {
                                $sname = $_.Name
                                if (-not $installedNames.ContainsKey($sname) -and -not $remoteNames.ContainsKey($sname)) {
                                    $script:MarketplaceAvailable += $sname
                                }
                            }
                        }
                    }
                }
            }
        }

        # d) Cache (plugins downloaded but maybe not in installed list)
        $cacheBase = Join-Path $sessDir 'cowork_pluginsche'
        if (Test-Path -LiteralPath $cacheBase -PathType Container) {
            Get-ChildItem -LiteralPath $cacheBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $cmpDir = $_.FullName
                $cmpName = $_.Name
                Get-ChildItem -LiteralPath $cmpDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $cpd = $_.FullName
                    $cpname = $_.Name
                    if ($installedNames.ContainsKey($cpname) -or $remoteNames.ContainsKey($cpname)) { return }

                    # Find latest version directory
                    $verDirs = @(Get-ChildItem -LiteralPath $cpd -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                    if ($verDirs.Count -eq 0) { return }
                    $latestVer = $verDirs[0].FullName
                    $cpjPath = Join-Path $latestVer '.claude-pluginplugin.json'
                    if (-not (Test-Path -LiteralPath $cpjPath -PathType Leaf)) { return }
                    $cpj = Read-SafeJson $cpjPath
                    if ($script:JsonError -or -not $cpj) { return }

                    $cn = Get-JsonProp $cpj 'name'
                    if (-not $cn) { $cn = $cpname }
                    $cv = Get-JsonProp $cpj 'version'
                    $ca = Get-AuthorName $cpj
                    $cd = Get-JsonProp $cpj 'description'

                    $script:PlgNames       += $cn
                    $script:PlgVers        += $cv
                    $script:PlgSrcs        += 'cached'
                    $script:PlgScopes      += ''
                    $script:PlgAuthors     += $ca
                    $script:PlgDescs       += $cd
                    $script:PlgMps         += $cmpName
                    $script:PlgInstalledAts += ''
                    $script:PlgSkillCounts += 0
                }
            }
        }
    }

    # Deduplicate marketplace available
    $script:MarketplaceAvailable = @($script:MarketplaceAvailable | Select-Object -Unique)
}

# ============================================================================
# 7. Collect-PluginHooks
# ============================================================================
function Collect-PluginHooks {
    param([string]$HomeDir)
    $seenHooks = @{}
    $allHookFiles = @()

    # Session-scoped hook paths
    $sessionGlobs = @(
        'cowork_plugins\cache\*\*\hooks\hooks.json',
        'local_*\.claude\plugins\marketplaces\*\plugins\*\hooks\hooks.json',
        'local_*\.claude\plugins\marketplaces\*\external_plugins\*\hooks\hooks.json',
        'remote_cowork_plugins\*\hooks\hooks.json'
    )

    foreach ($sessDir in $script:SessionDirs) {
        foreach ($glob in $sessionGlobs) {
            $pattern = Join-Path $sessDir $glob
            Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
                $allHookFiles += $_.FullName
            }
        }
    }

    # CC-level hook paths
    $ccGlobs = @(
        (Join-Path $HomeDir '.claude\plugins\marketplaces\*\plugins\*\hooks\hooks.json'),
        (Join-Path $HomeDir '.claude\plugins\marketplaces\*\external_plugins\*\hooks\hooks.json')
    )
    foreach ($glob in $ccGlobs) {
        Get-ChildItem -Path $glob -File -ErrorAction SilentlyContinue | ForEach-Object {
            $allHookFiles += $_.FullName
        }
    }

    foreach ($hp in $allHookFiles) {
        $hdata = Read-SafeJson $hp
        if ($script:JsonError -or -not $hdata) { continue }

        # Derive plugin name from path
        $pname = 'unknown'
        if ($hp -match '[/\\]plugins[/\\]([^/\\]+)[/\\]hooks[/\\]') {
            $pname = $Matches[1]
        } elseif ($hp -match '[/\\]cache[/\\][^/\\]+[/\\]([^/\\]+)[/\\][^/\\]+[/\\]hooks[/\\]') {
            $pname = $Matches[1]
        } elseif ($hp -match '[/\\]remote_cowork_plugins[/\\]([^/\\]+)[/\\]hooks[/\\]') {
            $pname = $Matches[1]
        }

        if (-not $hdata.PSObject.Properties['hooks']) { continue }
        $hdata.hooks.PSObject.Properties | ForEach-Object {
            $ev = $_.Name
            $evData = $_.Value
            if ($evData -isnot [array]) { $evData = @($evData) }
            foreach ($hookGroup in $evData) {
                if (-not ($hookGroup -is [PSCustomObject])) { continue }
                if (-not $hookGroup.PSObject.Properties['hooks']) { continue }
                $hookList = $hookGroup.hooks
                if ($hookList -isnot [array]) { $hookList = @($hookList) }
                foreach ($hook in $hookList) {
                    if (-not ($hook -is [PSCustomObject])) { continue }
                    if (-not $hook.PSObject.Properties['type'] -or "$($hook.type)" -ne 'command') { continue }
                    if (-not $hook.PSObject.Properties['command']) { continue }
                    $cmd = "$($hook.command)"
                    $dedupKey = "$pname|$ev|$cmd"
                    if ($seenHooks.ContainsKey($dedupKey)) { continue }
                    $seenHooks[$dedupKey] = $true
                    $script:HookPlugins += $pname
                    $script:HookEvents  += $ev
                    $script:HookCmds    += $cmd
                }
            }
        }
    }

    if ($script:HookPlugins.Count -gt 0) {
        $uniquePlugins = ($script:HookPlugins | Sort-Object -Unique) -join ', '
        Add-Finding 'WARN' 'Security' "$($script:HookPlugins.Count) plugin hook(s) found executing commands on lifecycle events" "Plugins: $uniquePlugins"
    }
}

# ============================================================================
# 8a. Read-BootstrapIdentity — extract account email/name from IndexedDB blobs
# ============================================================================
function Read-BootstrapIdentity {
    <#
    .SYNOPSIS
        Reads the Electron IndexedDB blob storage for the claude.ai origin and
        extracts the account email_address and full_name from the V8-serialized
        bootstrap/account cache.  Returns @{ Email; FullName } or $null.

        The Chromium IndexedDB stores large values as blob files under:
          IndexedDB/https_claude.ai_0.indexeddb.blob/

        The bootstrap account object is V8-serialized (not JSON).  Strings are
        encoded as 0x22 (one-byte tag) + varint length + UTF-8 bytes.  We locate
        the "email_address" key bytes and then read the immediately following
        V8 string which contains the actual email value.
    #>
    param([string]$ClaudeDir)

    $blobDir = Join-Path $ClaudeDir 'IndexedDB\https_claude.ai_0.indexeddb.blob'
    if (-not (Test-Path -LiteralPath $blobDir -PathType Container)) { return $null }

    $maxFileSize = 20 * 1024 * 1024  # 20 MB safety limit

    # V8 string tag is 0x22 followed by a varint-encoded length, then UTF-8 bytes.
    # For lengths < 128, the varint is a single byte.
    # For lengths >= 128, varint uses two bytes: (low7 | 0x80), (high7).
    # We search for the key "email_address" and "full_name" as V8 strings.
    $emailKeyBytes = [System.Text.Encoding]::UTF8.GetBytes('email_address')
    $nameKeyBytes  = [System.Text.Encoding]::UTF8.GetBytes('full_name')

    # Helper: read a V8 string starting at offset $pos (expects 0x22 tag at $pos)
    # Returns @{ Value; EndPos } or $null
    function Read-V8String {
        param([byte[]]$Bytes, [int]$Pos)
        if ($Pos -ge $Bytes.Length -or $Bytes[$Pos] -ne 0x22) { return $null }
        $Pos++
        # Decode varint length
        $strLen = 0; $shift = 0
        while ($Pos -lt $Bytes.Length) {
            $b = $Bytes[$Pos]; $Pos++
            $strLen = $strLen -bor (($b -band 0x7F) -shl $shift)
            $shift += 7
            if (($b -band 0x80) -eq 0) { break }
            if ($shift -gt 28) { return $null }  # sanity limit
        }
        if ($strLen -le 0 -or ($Pos + $strLen) -gt $Bytes.Length) { return $null }
        $val = [System.Text.Encoding]::UTF8.GetString($Bytes, $Pos, $strLen)
        return @{ Value = $val; EndPos = ($Pos + $strLen) }
    }

    # Helper: find byte sequence needle in haystack starting at offset
    function Find-ByteSequence {
        param([byte[]]$Haystack, [byte[]]$Needle, [int]$StartAt = 0)
        $limit = $Haystack.Length - $Needle.Length
        for ($i = $StartAt; $i -le $limit; $i++) {
            $match = $true
            for ($j = 0; $j -lt $Needle.Length; $j++) {
                if ($Haystack[$i + $j] -ne $Needle[$j]) { $match = $false; break }
            }
            if ($match) { return $i }
        }
        return -1
    }

    $blobFiles = Get-ChildItem -LiteralPath $blobDir -Recurse -File -ErrorAction SilentlyContinue |
                 Sort-Object Length -Descending  # larger files more likely to have bootstrap

    foreach ($bf in $blobFiles) {
        if ($bf.Length -gt $maxFileSize -or $bf.Length -lt 200) { continue }
        try {
            $fileBytes = [System.IO.File]::ReadAllBytes($bf.FullName)
        } catch { continue }

        # Search for "email_address" key (V8 string: 0x22 + len + bytes)
        $emailKeyIdx = Find-ByteSequence $fileBytes $emailKeyBytes
        if ($emailKeyIdx -lt 0) { continue }

        # The value V8 string follows immediately after the key
        $valPos = $emailKeyIdx + $emailKeyBytes.Length
        $emailResult = Read-V8String $fileBytes $valPos
        if (-not $emailResult -or -not $emailResult.Value) { continue }

        $foundEmail = $emailResult.Value
        # Sanity: must look like an email
        if ($foundEmail -notmatch '@.+\..+') { continue }

        # Now find full_name nearby (search from start of this account object area)
        $searchFrom = [Math]::Max(0, $emailKeyIdx - 200)
        $nameKeyIdx = Find-ByteSequence $fileBytes $nameKeyBytes $searchFrom
        $foundName = ''
        if ($nameKeyIdx -ge 0) {
            $nameValPos = $nameKeyIdx + $nameKeyBytes.Length
            $nameResult = Read-V8String $fileBytes $nameValPos
            if ($nameResult -and $nameResult.Value) {
                $foundName = $nameResult.Value
            }
        }

        return @{ Email = $foundEmail; FullName = $foundName }
    }

    return $null
}

# ============================================================================
# 8. Collect-Workspaces
# ============================================================================
function Collect-Workspaces {
    param([string]$ClaudeDir)
    $sessionsDir = Join-Path $ClaudeDir 'local-agent-mode-sessions'
    if (-not (Test-Path -LiteralPath $sessionsDir -PathType Container)) { return }

    # Pre-fetch bootstrap identity from IndexedDB (fallback for missing session files)
    $bootstrapId = Read-BootstrapIdentity $ClaudeDir

    # Discover org/user pairs
    Get-ChildItem -LiteralPath $sessionsDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' -and $_.Name -ne 'skills-plugin' } | ForEach-Object {
        $orgName = $_.Name
        $script:WsOrgUuid = $orgName

        Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | ForEach-Object {
            $uid = $_.Name
            $userDir = $_.FullName
            $script:WsUuids += $uid

            # Count session files
            $sc = @(Get-ChildItem -LiteralPath $userDir -Filter 'local_*.json' -File -ErrorAction SilentlyContinue).Count
            $script:WsSessionCounts += $sc

            # Get account name/email from first session file with data
            $acct = ''; $email = ''
            $sessionFiles = Get-ChildItem -LiteralPath $userDir -Filter 'local_*.json' -File -ErrorAction SilentlyContinue
            foreach ($sf in $sessionFiles) {
                $sfData = Read-SafeJson $sf.FullName
                if ($script:JsonError -or -not $sfData) { continue }
                if ($sfData.PSObject.Properties['accountName'] -and $sfData.accountName -and "$($sfData.accountName)" -ne 'null') {
                    $acct = "$($sfData.accountName)"
                    if ($sfData.PSObject.Properties['emailAddress'] -and $sfData.emailAddress -and "$($sfData.emailAddress)" -ne 'null') {
                        $email = "$($sfData.emailAddress)"
                    }
                    break
                }
            }

            # Fallback: use bootstrap identity from IndexedDB if session files lack data
            if (-not $email -and $bootstrapId) {
                $email = $bootstrapId.Email
                if (-not $acct -and $bootstrapId.FullName) {
                    $acct = $bootstrapId.FullName
                }
            }

            $script:WsAcctNames += $acct
            $script:WsEmails    += $email

            # DXT allowlist for this user UUID
            $dxtVal = 'unset'
            $rawConfig = $script:AppConfig['_raw_config']
            if ($rawConfig -and $rawConfig -is [PSCustomObject]) {
                $dxtKey = "dxt:allowlistEnabled:$uid"
                if ($rawConfig.PSObject.Properties[$dxtKey]) {
                    $dxtVal = "$($rawConfig.$dxtKey)"
                }
            }
            $script:WsDxtAllowlists += $dxtVal

            # Remote plugins directory presence
            $rpDir = Join-Path $userDir 'remote_cowork_plugins'
            $script:WsHasRemotePlugins += (Test-Path -LiteralPath $rpDir -PathType Container)

            # Bridge active placeholder (updated below)
            $script:WsBridgeActive += $false
        }
    }

    # Check config.json for user UUIDs with DXT entries but no session dir
    $configPath = Join-Path $ClaudeDir 'config.json'
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        $cfgData = Read-SafeJson $configPath
        if (-not $script:JsonError -and $cfgData) {
            $cfgData.PSObject.Properties | Where-Object { $_.Name -match '^dxt:allowlistEnabled:(.+)$' } | ForEach-Object {
                $duid = $Matches[1]
                if ($duid -notin $script:WsUuids) {
                    $script:WsUuids         += $duid
                    $script:WsSessionCounts += 0
                    $script:WsAcctNames     += $(if ($bootstrapId -and $bootstrapId.FullName) { $bootstrapId.FullName } else { '' })
                    $script:WsEmails        += $(if ($bootstrapId -and $bootstrapId.Email) { $bootstrapId.Email } else { '' })
                    $script:WsDxtAllowlists += "$($_.Value)"
                    # Check for remote plugins dir
                    $hasRemote = $false
                    if ($script:WsOrgUuid) {
                        $rpCheck = Join-Path (Join-Path (Join-Path $sessionsDir $script:WsOrgUuid) $duid) 'remote_cowork_plugins'
                        $hasRemote = Test-Path -LiteralPath $rpCheck -PathType Container
                    }
                    $script:WsHasRemotePlugins += $hasRemote
                    $script:WsBridgeActive     += $false
                }
            }
        }
    }

    # Bridge-state.json for dispatch detection
    $bridgePath = Join-Path $ClaudeDir 'bridge-state.json'
    $bridgeData = Read-SafeJson $bridgePath
    if (-not $script:JsonError -and $bridgeData) {
        $bridgeData.PSObject.Properties | ForEach-Object {
            $bk = $_.Name
            $bVal = $_.Value
            $bUid = ($bk -split ':')[0]

            $bEnabled   = $false
            $bConsented = $false
            if ($bVal -is [PSCustomObject]) {
                if ($bVal.PSObject.Properties['enabled']      -and "$($bVal.enabled)"      -match '^[Tt]rue$') { $bEnabled = $true }
                if ($bVal.PSObject.Properties['userConsented'] -and "$($bVal.userConsented)" -match '^[Tt]rue$') { $bConsented = $true }
            }
            if ($bEnabled) { $script:DispatchBridgeEnabled = $true }
            if ($bConsented) { $script:DispatchBridgeConsented = $true }

            # Mark bridge active for matching workspace
            for ($wi = 0; $wi -lt $script:WsUuids.Count; $wi++) {
                if ($script:WsUuids[$wi] -eq $bUid) {
                    $script:WsBridgeActive[$wi] = $true
                }
            }
        }
    }

    # Workspace findings
    if ($script:WsUuids.Count -gt 1) {
        Add-Finding 'INFO' 'Workspaces' "$($script:WsUuids.Count) workspace(s) detected in Claude Desktop" "org=$($script:WsOrgUuid)"
    }
    if ($script:DispatchBridgeEnabled) {
        Add-Finding 'WARN' 'Cowork Settings' 'Dispatch bridge is CONFIGURED - mobile device can dispatch tasks to this desktop' "bridge-state.json: enabled=true, userConsented=$($script:DispatchBridgeConsented)"
    }
}

# ============================================================================
# 9a. LevelDB / Snappy helpers for reading Electron Local Storage
# ============================================================================

function Read-LevelDbVarint {
    <# Reads a LevelDB-style unsigned varint from a byte array at the given offset.
       Returns @{ Value; NextOffset }. #>
    param([byte[]]$Bytes, [int]$Offset)
    $result = [long]0; $shift = 0; $pos = $Offset
    do {
        $b = $Bytes[$pos]; $pos++
        $result = $result -bor (([long]($b -band 0x7F)) -shl $shift)
        $shift += 7
    } while (($b -band 0x80) -and $pos -lt $Bytes.Length)
    return @{ Value = $result; NextOffset = $pos }
}

function Expand-SnappyBlock {
    <# Decompresses a Snappy-compressed byte range.  Returns decompressed byte[].
       Returns $null on any error (corrupt data, truncated stream, etc.). #>
    param([byte[]]$Data, [int]$Offset, [int]$Length)
    try {
        $pos = $Offset; $end = $Offset + $Length
        # Varint: uncompressed length
        $uncompLen = 0; $shift = 0
        do { $b = $Data[$pos]; $pos++; $uncompLen = $uncompLen -bor (($b -band 0x7F) -shl $shift); $shift += 7 } while (($b -band 0x80) -and $pos -lt $end)
        if ($uncompLen -le 0 -or $uncompLen -gt 64 * 1024 * 1024) { return $null }  # sanity cap 64 MB
        $out = New-Object byte[] $uncompLen
        $op  = 0
        while ($pos -lt $end -and $op -lt $uncompLen) {
            $tag     = $Data[$pos]; $pos++
            $tagType = $tag -band 3
            switch ($tagType) {
                0 { # literal
                    $litLen = $tag -shr 2
                    if    ($litLen -lt 60) { $litLen++ }
                    elseif ($litLen -eq 60) { $litLen = [int]$Data[$pos] + 1; $pos++ }
                    elseif ($litLen -eq 61) { $litLen = [int]$Data[$pos] + ([int]$Data[$pos+1] -shl 8) + 1; $pos += 2 }
                    elseif ($litLen -eq 62) { $litLen = [int]$Data[$pos] + ([int]$Data[$pos+1] -shl 8) + ([int]$Data[$pos+2] -shl 16) + 1; $pos += 3 }
                    else                    { $litLen = [int]$Data[$pos] + ([int]$Data[$pos+1] -shl 8) + ([int]$Data[$pos+2] -shl 16) + ([int]$Data[$pos+3] -shl 24) + 1; $pos += 4 }
                    if (($pos + $litLen) -gt $end -or ($op + $litLen) -gt $uncompLen) { return $null }
                    [Array]::Copy($Data, $pos, $out, $op, $litLen)
                    $pos += $litLen; $op += $litLen
                }
                1 { # copy, 1-byte offset
                    $cpLen = (($tag -shr 2) -band 7) + 4
                    $cpOff = (([int]($tag -band 0xE0)) -shl 3) -bor [int]$Data[$pos]; $pos++
                    if ($cpOff -eq 0 -or $cpOff -gt $op -or ($op + $cpLen) -gt $uncompLen) { return $null }
                    for ($ci = 0; $ci -lt $cpLen; $ci++) { $out[$op] = $out[$op - $cpOff]; $op++ }
                }
                2 { # copy, 2-byte offset
                    $cpLen = ($tag -shr 2) + 1
                    $cpOff = [int]$Data[$pos] + ([int]$Data[$pos+1] -shl 8); $pos += 2
                    if ($cpOff -eq 0 -or $cpOff -gt $op -or ($op + $cpLen) -gt $uncompLen) { return $null }
                    for ($ci = 0; $ci -lt $cpLen; $ci++) { $out[$op] = $out[$op - $cpOff]; $op++ }
                }
                3 { # copy, 4-byte offset
                    $cpLen = ($tag -shr 2) + 1
                    $cpOff = [int]$Data[$pos] + ([int]$Data[$pos+1] -shl 8) + ([int]$Data[$pos+2] -shl 16) + ([int]$Data[$pos+3] -shl 24); $pos += 4
                    if ($cpOff -eq 0 -or $cpOff -gt $op -or ($op + $cpLen) -gt $uncompLen) { return $null }
                    for ($ci = 0; $ci -lt $cpLen; $ci++) { $out[$op] = $out[$op - $cpOff]; $op++ }
                }
            }
        }
        return ,$out
    } catch {
        return $null
    }
}

function Read-SstableValue {
    <# Reads a specific key's value from a LevelDB SSTable (.ldb) file.
       The SSTable format stores data in Snappy-compressed blocks; the footer and
       index block tell us where each data block lives.
       Returns the value as a byte[] or $null if not found. #>
    param([byte[]]$FileBytes, [string]$TargetKey)

    $fLen = $FileBytes.Length
    if ($fLen -lt 48) { return $null }  # too small for footer

    # ── Read footer (last 48 bytes): metaindex_handle, index_handle, padding, magic ──
    # SSTable magic number: 0xDB4775248B80FB57 (stored little-endian as bytes 57 FB 80 8B 24 75 47 DB)
    $magicBytes = @(0x57, 0xFB, 0x80, 0x8B, 0x24, 0x75, 0x47, 0xDB)
    $magicOk = $true
    for ($mi = 0; $mi -lt 8; $mi++) { if ($FileBytes[$fLen - 8 + $mi] -ne $magicBytes[$mi]) { $magicOk = $false; break } }
    if (-not $magicOk) { return $null }

    $footerStart = $fLen - 48
    $r = Read-LevelDbVarint $FileBytes $footerStart              # metaindex offset
    $r = Read-LevelDbVarint $FileBytes $r.NextOffset             # metaindex size
    $r = Read-LevelDbVarint $FileBytes $r.NextOffset             # index offset
    $idxOffset = [int]$r.Value
    $r = Read-LevelDbVarint $FileBytes $r.NextOffset             # index size
    $idxSize = [int]$r.Value

    if ($idxOffset + $idxSize -gt $fLen) { return $null }

    # ── Decompress the index block ──
    $idxCompType = $FileBytes[$idxOffset + $idxSize]             # 0=none, 1=snappy
    $idxBlock = $null
    if ($idxCompType -eq 1) {
        $idxBlock = Expand-SnappyBlock $FileBytes $idxOffset $idxSize
    } elseif ($idxCompType -eq 0) {
        $idxBlock = New-Object byte[] $idxSize
        [Array]::Copy($FileBytes, $idxOffset, $idxBlock, 0, $idxSize)
    }
    if (-not $idxBlock -or $idxBlock.Length -lt 4) { return $null }

    # ── Parse index block entries to find candidate data blocks ──
    $numRestarts = [System.BitConverter]::ToInt32($idxBlock, $idxBlock.Length - 4)
    $idxDataEnd  = $idxBlock.Length - 4 - ($numRestarts * 4)

    # Collect block handles: list of @{ Offset; Size; LastKey }
    $blockHandles = @()
    $pos = 0; $lastKeyBytes = [byte[]]@()
    while ($pos -lt $idxDataEnd) {
        $shared   = Read-LevelDbVarint $idxBlock $pos;        $pos = $shared.NextOffset
        $unshared = Read-LevelDbVarint $idxBlock $pos;        $pos = $unshared.NextOffset
        $valLen   = Read-LevelDbVarint $idxBlock $pos;        $pos = $valLen.NextOffset
        if ($pos + $unshared.Value -gt $idxDataEnd) { break }
        $kb = New-Object byte[] ([int]$shared.Value + [int]$unshared.Value)
        if ($shared.Value -gt 0 -and $lastKeyBytes.Length -ge $shared.Value) {
            [Array]::Copy($lastKeyBytes, 0, $kb, 0, [int]$shared.Value)
        }
        [Array]::Copy($idxBlock, $pos, $kb, [int]$shared.Value, [int]$unshared.Value)
        $pos += [int]$unshared.Value
        $lastKeyBytes = $kb
        # Block handle is stored in the value bytes
        $bOff = Read-LevelDbVarint $idxBlock $pos;  $pos = $bOff.NextOffset
        $bSz  = Read-LevelDbVarint $idxBlock $pos;  $pos = $bSz.NextOffset
        $blockHandles += @{ Offset = [int]$bOff.Value; Size = [int]$bSz.Value; LastKey = $kb }
    }

    # ── For each data block, decompress and search for the target key ──
    $targetKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($TargetKey)
    foreach ($bh in $blockHandles) {
        if ($bh.Offset + $bh.Size -gt $fLen) { continue }
        $compType = $FileBytes[$bh.Offset + $bh.Size]
        $block = $null
        if ($compType -eq 1) {
            $block = Expand-SnappyBlock $FileBytes $bh.Offset $bh.Size
        } elseif ($compType -eq 0) {
            $block = New-Object byte[] $bh.Size
            [Array]::Copy($FileBytes, $bh.Offset, $block, 0, $bh.Size)
        }
        if (-not $block -or $block.Length -lt 4) { continue }

        # Parse the data block: entries are prefix-compressed key-value pairs
        $nRestart = [System.BitConverter]::ToInt32($block, $block.Length - 4)
        $dEnd     = $block.Length - 4 - ($nRestart * 4)
        $bp = 0; $lastK = [byte[]]@()
        while ($bp -lt $dEnd) {
            $sh = Read-LevelDbVarint $block $bp;  $bp = $sh.NextOffset
            $un = Read-LevelDbVarint $block $bp;  $bp = $un.NextOffset
            $vl = Read-LevelDbVarint $block $bp;  $bp = $vl.NextOffset
            if ($bp + $un.Value -gt $dEnd) { break }
            $fk = New-Object byte[] ([int]$sh.Value + [int]$un.Value)
            if ($sh.Value -gt 0 -and $lastK.Length -ge $sh.Value) {
                [Array]::Copy($lastK, 0, $fk, 0, [int]$sh.Value)
            }
            [Array]::Copy($block, $bp, $fk, [int]$sh.Value, [int]$un.Value)
            $bp += [int]$un.Value
            $lastK = $fk
            $valStart = $bp; $bp += [int]$vl.Value

            # Internal key = user_key + 8 bytes (sequence_number[7] + type[1])
            # User key for Electron Local Storage = _origin \x00 \x01 key_name
            if ($fk.Length -le 8) { continue }
            $userKeyLen = $fk.Length - 8
            # Check if the user key ends with \x00\x01 + targetKey
            # Minimum: origin(1+) + \x00 + \x01 + targetKeyBytes.Length
            if ($userKeyLen -lt $targetKeyBytes.Length + 2) { continue }
            $tkStart = $userKeyLen - $targetKeyBytes.Length
            # Verify the key name matches
            $match = $true
            for ($mi = 0; $mi -lt $targetKeyBytes.Length; $mi++) {
                if ($fk[$tkStart + $mi] -ne $targetKeyBytes[$mi]) { $match = $false; break }
            }
            if (-not $match) { continue }
            # Verify separator bytes: \x00\x01 immediately before the key name
            if ($tkStart -lt 2 -or $fk[$tkStart - 2] -ne 0x00 -or $fk[$tkStart - 1] -ne 0x01) { continue }

            # Extract the value bytes
            if ($vl.Value -gt 0 -and $valStart + $vl.Value -le $block.Length) {
                $valBytes = New-Object byte[] ([int]$vl.Value)
                [Array]::Copy($block, $valStart, $valBytes, 0, [int]$vl.Value)
                return ,$valBytes
            }
        }
    }
    return $null
}

function Read-LogFileValue {
    <# Searches a LevelDB .log (WAL) file for a key's value.
       WAL records are NOT Snappy-compressed — they use a simple record format.
       Each record: checksum(4) + length(2) + type(1) + payload.
       Payload for Put: sequence(8) + count(4) + [type(1)=1 + key_len(varint) + key + val_len(varint) + val]...
       Returns value as byte[] or $null. #>
    param([byte[]]$FileBytes, [string]$TargetKey)

    $fLen = $FileBytes.Length
    $targetKeyBytes = [System.Text.Encoding]::UTF8.GetBytes($TargetKey)
    # We search for the raw target key in the file and then try to parse the surrounding record
    # This is a pragmatic approach: scan for the key bytes, then look for JSON after it.
    # In WAL files, the data is uncompressed, so direct text search works.
    $keyIdx = -1
    $searchLimit = $fLen - $targetKeyBytes.Length
    for ($i = 0; $i -le $searchLimit; $i++) {
        $found = $true
        for ($j = 0; $j -lt $targetKeyBytes.Length; $j++) {
            if ($FileBytes[$i + $j] -ne $targetKeyBytes[$j]) { $found = $false; break }
        }
        if ($found) { $keyIdx = $i; break }
    }
    if ($keyIdx -lt 0) { return $null }

    # WAL data is uncompressed — scan forward from key end for JSON value
    $scanStart = $keyIdx + $targetKeyBytes.Length
    $jsonStart = -1
    $scanEnd = [Math]::Min($scanStart + 512, $fLen)
    for ($sp = $scanStart; $sp -lt $scanEnd; $sp++) {
        if ($FileBytes[$sp] -eq 0x7B) { $jsonStart = $sp; break }
    }
    if ($jsonStart -lt 0) { return $null }

    # Extract balanced JSON
    $depth = 0; $jsonEnd = -1
    for ($sp = $jsonStart; $sp -lt $fLen; $sp++) {
        $b = $FileBytes[$sp]
        if ($b -eq 0x7B) { $depth++ }
        elseif ($b -eq 0x7D) { $depth--; if ($depth -eq 0) { $jsonEnd = $sp; break } }
    }
    if ($jsonEnd -lt 0) { return $null }

    $valLen = $jsonEnd - $jsonStart + 1
    $valBytes = New-Object byte[] $valLen
    [Array]::Copy($FileBytes, $jsonStart, $valBytes, 0, $valLen)
    return ,$valBytes
}

# ============================================================================
# 9a-1. Read-LevelDbValue — generic key reader for Electron Local Storage LevelDB
# ============================================================================
function Read-LevelDbValue {
    <#
    .SYNOPSIS
        Reads any key from Electron Local Storage LevelDB.
        Returns decoded string value or $null.
    #>
    param([string]$ClaudeDir, [string]$KeyName)

    $leveldbDir = Join-Path $ClaudeDir 'Local Storage\leveldb'
    if (-not (Test-Path -LiteralPath $leveldbDir -PathType Container)) { return $null }

    $maxFileSize = 100 * 1024 * 1024  # 100MB safety limit (react-query-cache can be large)
    $dbFiles = Get-ChildItem -LiteralPath $leveldbDir -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Extension -in '.ldb', '.log' } |
               Sort-Object LastWriteTime -Descending

    foreach ($dbFile in $dbFiles) {
        if ($dbFile.Length -gt $maxFileSize -or $dbFile.Length -lt 48) { continue }
        try { $fileBytes = [System.IO.File]::ReadAllBytes($dbFile.FullName) } catch { continue }

        $valBytes = $null
        if ($dbFile.Extension -eq '.ldb') {
            $valBytes = Read-SstableValue $fileBytes $KeyName
        } elseif ($dbFile.Extension -eq '.log') {
            $valBytes = Read-LogFileValue $fileBytes $KeyName
        }
        if (-not $valBytes -or $valBytes.Length -eq 0) { continue }

        # Chromium Local Storage value prefix: 0x00 = UTF-16LE, 0x01 = Latin-1/UTF-8
        if ($valBytes.Length -gt 1 -and $valBytes[0] -eq 0x00) {
            return [System.Text.Encoding]::Unicode.GetString($valBytes, 1, $valBytes.Length - 1)
        } elseif ($valBytes.Length -gt 1 -and $valBytes[0] -eq 0x01) {
            return [System.Text.Encoding]::UTF8.GetString($valBytes, 1, $valBytes.Length - 1)
        } else {
            return [System.Text.Encoding]::UTF8.GetString($valBytes)
        }
    }
    return $null
}

# ============================================================================
# 9a-2. Resolve-ConnectorUuidNames — maps UUIDs to display names via react-query cache
# ============================================================================
function Resolve-ConnectorUuidNames {
    <#
    .SYNOPSIS
        Reads react-query-cache-ls from LevelDB and resolves UUID -> connector name.
        Uses two dynamic strategies (no hardcoded connector lists):
        1. Gateway tool-join: local:harmonic-mcp-gateway:<Name>__<tool> entries share
           tool names with <UUID>:<tool> entries, allowing name resolution.
        2. Known-name matching: tool names matched against connector names discovered
           from external_plugins directories and marketplace.json.
        Returns a hashtable of UUID -> display_name.
    #>
    param([string]$ClaudeDir)

    $result = @{}
    $rqs = Read-LevelDbValue -ClaudeDir $ClaudeDir -KeyName 'react-query-cache-ls'
    if (-not $rqs -or $rqs.Length -lt 100) { return $result }

    # Extract UUID -> tools mapping
    $uuidTools = @{}
    $ms = [regex]::Matches($rqs, '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([a-zA-Z][a-zA-Z0-9_-]+)')
    foreach ($m in $ms) {
        $u = $m.Groups[1].Value
        $t = $m.Groups[2].Value -replace '-[0-9a-f]{32}$', ''
        if (-not $uuidTools.ContainsKey($u)) { $uuidTools[$u] = @() }
        if ($t -notin $uuidTools[$u]) { $uuidTools[$u] += $t }
    }

    # Extract gateway connector Name -> tools mapping
    $gwTools = @{}
    $gwms = [regex]::Matches($rqs, 'local:harmonic-mcp-gateway:([^_"]+)__([a-zA-Z][a-zA-Z0-9_-]+)')
    foreach ($m in $gwms) {
        $name = $m.Groups[1].Value
        $tool = $m.Groups[2].Value -replace '-[0-9a-f]{32}$', ''
        if (-not $gwTools.ContainsKey($name)) { $gwTools[$name] = @() }
        if ($tool -notin $gwTools[$name]) { $gwTools[$name] += $tool }
    }

    # Step 1: Match UUIDs to gateway names via shared tools
    foreach ($u in $uuidTools.Keys) {
        foreach ($gwName in $gwTools.Keys) {
            $shared = $uuidTools[$u] | Where-Object { $_ -in $gwTools[$gwName] }
            if ($shared) {
                $result[$u] = $gwName
                break
            }
        }
    }

    # Step 2: For unmatched UUIDs, match tool names against known connectors dynamically
    # Sources: external_plugins directories + marketplace.json names
    $knownNames = @{}
    $epDirs = Get-ChildItem "$env:USERPROFILE\.claude\plugins\marketplaces\*\external_plugins\*" -Directory -ErrorAction SilentlyContinue
    foreach ($d in $epDirs) { $knownNames[$d.Name.ToLower()] = $d.Name }
    $mjPath = Join-Path $env:USERPROFILE '.claude\plugins\marketplaces\claude-plugins-official\.claude-plugin\marketplace.json'
    if (Test-Path $mjPath) {
        try {
            $mjRaw = Get-Content $mjPath -Raw
            $mjNames = [regex]::Matches($mjRaw, '"name"\s*:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
            foreach ($mn in $mjNames) {
                $lk = $mn.ToLower()
                if (-not $knownNames.ContainsKey($lk)) { $knownNames[$lk] = $mn }
            }
        } catch {}
    }

    foreach ($u in $uuidTools.Keys) {
        if ($result.ContainsKey($u)) { continue }
        foreach ($t in $uuidTools[$u]) {
            $tl = $t.ToLower()
            foreach ($sn in $knownNames.Keys) {
                if ($sn.Length -ge 4 -and ($tl.Contains($sn) -or $tl.StartsWith("${sn}_") -or $tl.StartsWith("${sn}-"))) {
                    $result[$u] = $knownNames[$sn]
                    break
                }
            }
            if ($result.ContainsKey($u)) { break }
        }
    }

    # Store tool counts for later use
    $script:UuidToolCounts = @{}
    foreach ($u in $uuidTools.Keys) { $script:UuidToolCounts[$u] = $uuidTools[$u].Count }

    # Store gateway connector names for "not connected" detection
    $script:GatewayConnectorNames = @($gwTools.Keys)

    return $result
}

# ============================================================================
# 9a-3. Read-GoogleConnectorState — reads Google connector auth from Session Storage
# ============================================================================
function Read-GoogleConnectorState {
    <#
    .SYNOPSIS
        Reads Google connector authentication status from Electron Session Storage.
        Returns hashtable of display_name -> $true/$false (isAuthenticated).
    #>
    param([string]$ClaudeDir)

    $result = @{}
    $sessDir = Join-Path $ClaudeDir 'Session Storage'
    if (-not (Test-Path -LiteralPath $sessDir -PathType Container)) { return $result }

    $gmap = @{ 'gcal' = 'Google Calendar'; 'gdrive' = 'Google Drive'; 'gmail' = 'Gmail' }

    $logFiles = Get-ChildItem -LiteralPath $sessDir -Filter '*.log' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending
    foreach ($lf in $logFiles) {
        try {
            $fs = [System.IO.File]::Open($lf.FullName, 'Open', 'Read', 'ReadWrite')
            $sb = New-Object byte[] $fs.Length
            [void]$fs.Read($sb, 0, $fs.Length)
            $fs.Close()
        } catch { continue }

        $st = [System.Text.Encoding]::Unicode.GetString($sb)
        $bestExp = [long]0; $bestObj = $null
        foreach ($bm in [regex]::Matches($st, '\{"statuses":\{')) {
            $d = 0; $ei = $bm.Index
            for ($i = $bm.Index; $i -lt $st.Length; $i++) {
                if ($st[$i] -eq '{') { $d++ } elseif ($st[$i] -eq '}') { $d--; if ($d -eq 0) { $ei = $i; break } }
            }
            if ($ei -gt $bm.Index) {
                try {
                    $o = $st.Substring($bm.Index, $ei - $bm.Index + 1) | ConvertFrom-Json
                    if ($o.PSObject.Properties['expiry'] -and $o.expiry -gt $bestExp) {
                        $bestExp = $o.expiry; $bestObj = $o
                    }
                } catch {}
            }
        }
        if ($bestObj -and $bestObj.PSObject.Properties['statuses']) {
            foreach ($p in $bestObj.statuses.PSObject.Properties) {
                $dn = if ($gmap.ContainsKey($p.Name)) { $gmap[$p.Name] } else { $p.Name }
                $result[$dn] = ("$($p.Value.isAuthenticated)" -match '^[Tt]rue$')
            }
            break  # found the most recent, stop
        }
    }
    return $result
}

# ============================================================================
# 9a-4. Read-LevelDbConnectorState
# ============================================================================
function Read-LevelDbConnectorState {
    <#
    .SYNOPSIS
        Reads mcp-remote-connectors-state from Electron Local Storage LevelDB.
        Returns hashtable of UUID -> @{ IsConnected; HasPromptsOrResources; Expiration }
        or $null if unreadable.
    #>
    param([string]$ClaudeDir)

    $jsonStr = Read-LevelDbValue -ClaudeDir $ClaudeDir -KeyName 'mcp-remote-connectors-state'
    if (-not $jsonStr) { return $null }

    # Trim to JSON object (in case there is leading data)
    $braceStart = $jsonStr.IndexOf('{')
    if ($braceStart -lt 0) { return $null }
    if ($braceStart -gt 0) { $jsonStr = $jsonStr.Substring($braceStart) }

    try {
        $parsed = $jsonStr | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }

    $result = @{}
    foreach ($prop in $parsed.PSObject.Properties) {
        $val = $prop.Value
        $isConn = $false; $hasPR = $false; $exp = [long]0
        if ($val -is [PSCustomObject]) {
            if ($val.PSObject.Properties['isConnected']) {
                $isConn = "$($val.isConnected)" -match '^[Tt]rue$'
            }
            if ($val.PSObject.Properties['hasPromptsOrResources']) {
                $hasPR = "$($val.hasPromptsOrResources)" -match '^[Tt]rue$'
            }
            if ($val.PSObject.Properties['expiration']) {
                try { $exp = [long]"$($val.expiration)" } catch { $exp = 0 }
            }
        }
        $result[$prop.Name] = @{
            IsConnected           = $isConn
            HasPromptsOrResources = $hasPR
            Expiration            = $exp
        }
    }

    if ($result.Count -gt 0) { return $result }
    return $null
}

# ============================================================================
# 9. Collect-Connectors
# ============================================================================
function Collect-Connectors {
    param([string]$ClaudeDir)

    # Scan session files for egress policy, disabled tools, and dispatch state
    foreach ($sessDir in $script:SessionDirs) {
        $sessionFiles = Get-ChildItem -LiteralPath $sessDir -Filter 'local_*.json' -File -ErrorAction SilentlyContinue
        foreach ($entry in $sessionFiles) {
            $data = Read-SafeJson $entry.FullName
            if ($script:JsonError -or -not $data) { continue }

            # Egress policy (most-permissive wins)
            if ($data.PSObject.Properties['egressAllowedDomains'] -and $data.egressAllowedDomains) {
                $ead = $data.egressAllowedDomains
                if ($ead -is [array]) {
                    if ($ead.Count -eq 1 -and $ead[0] -eq '*') {
                        $script:EgressUnrestricted = $true
                        $script:EgressDomains = '*'
                    } elseif ($ead.Count -gt 0 -and -not $script:EgressUnrestricted) {
                        $script:EgressDomains = $ead -join ', '
                    }
                } elseif ("$ead" -eq '*') {
                    $script:EgressUnrestricted = $true
                    $script:EgressDomains = '*'
                }
            }

            # Disabled MCP tools
            if ($data.PSObject.Properties['enabledMcpTools'] -and $data.enabledMcpTools) {
                $data.enabledMcpTools.PSObject.Properties | Where-Object { "$($_.Value)" -match '^[Ff]alse$' } | ForEach-Object {
                    if ($_.Name -notin $script:DisabledMcpTools) {
                        $script:DisabledMcpTools += $_.Name
                    }
                }
            }

            # Dispatch detection (hostLoopMode)
            if ($data.PSObject.Properties['hostLoopMode'] -and "$($data.hostLoopMode)" -match '^[Tt]rue$') {
                $script:DispatchActive = $true
                $script:DispatchSessionCount++
            }
        }
    }

    # ── Read LevelDB for authoritative connector state ──
    $levelDbState = $null
    $levelDbError = $false
    try {
        $levelDbState = Read-LevelDbConnectorState -ClaudeDir $ClaudeDir
    } catch {
        $levelDbError = $true
    }

    # ── Resolve UUID -> display name via react-query cache gateway matching ──
    $script:UuidToolCounts = @{}
    $script:GatewayConnectorNames = @()
    $uuidToName = @{}
    try {
        $uuidToName = Resolve-ConnectorUuidNames -ClaudeDir $ClaudeDir
    } catch {}

    # ── Read Google connector state from Session Storage ──
    $googleState = @{}
    try {
        $googleState = Read-GoogleConnectorState -ClaudeDir $ClaudeDir
    } catch {}

    # ── Build display name normalization map from external_plugins ──
    $displayNames = @{}
    $epDirs = Get-ChildItem "$env:USERPROFILE\.claude\plugins\marketplaces\*\external_plugins\*" -Directory -ErrorAction SilentlyContinue
    foreach ($d in $epDirs) {
        $dn = (Get-Culture).TextInfo.ToTitleCase($d.Name.ToLower())
        switch ($d.Name.ToLower()) {
            'context7'     { $dn = 'Context7' }
            'github'       { $dn = 'GitHub' }
            'gitlab'       { $dn = 'GitLab' }
            'imessage'     { $dn = 'iMessage' }
            'laravel-boost'{ $dn = 'Laravel Boost' }
        }
        $displayNames[$d.Name.ToLower()] = $dn
    }

    # Normalize UUID->name display names
    foreach ($u in @($uuidToName.Keys)) {
        $lk = $uuidToName[$u].ToLower()
        if ($displayNames.ContainsKey($lk)) {
            $uuidToName[$u] = $displayNames[$lk]
        }
    }

    $seenWebNorm = @{}
    $nowMs = [long]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())

    if ($levelDbState -and $levelDbState.Count -gt 0) {
        # ── LevelDB is authoritative: iterate over its entries ──
        $connectedUuids    = @{}  # norm -> "name|toolCount"
        $notConnectedUuids = @{}  # norm -> display name
        $expiredUuids      = @()  # list of names with expired auth

        $uuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        foreach ($uuid in ($levelDbState.Keys | Sort-Object)) {
            $state = $levelDbState[$uuid]
            $displayName = if ($uuidToName.ContainsKey($uuid)) { $uuidToName[$uuid] } else { $null }
            $toolCount   = if ($script:UuidToolCounts.ContainsKey($uuid)) { "$($script:UuidToolCounts[$uuid])" }
                           else { '0' }

            # Skip unresolved UUIDs with 0 tools — multi-org duplicates with no client-side name data
            if (-not $displayName -and $toolCount -eq '0') { continue }
            if (-not $displayName) { $displayName = $uuid }

            $normKey = $displayName.ToLower()

            if ($state.IsConnected) {
                $connectedUuids[$normKey] = "$displayName|$toolCount"
                if ($state.Expiration -gt 0 -and $state.Expiration -lt $nowMs) {
                    $expiredUuids += $displayName
                }
            } else {
                $notConnectedUuids[$normKey] = $displayName
            }
        }

        # Deduplicate connected: same display name across orgs
        $seenConnected = @{}
        foreach ($key in ($connectedUuids.Keys | Sort-Object)) {
            $val   = $connectedUuids[$key]
            $parts = $val -split '\|', 2
            $cname = $parts[0]
            $ctc   = $parts[1]
            $norm = ($cname.ToLower() -replace '[ _]', '-') -replace '[^a-z0-9\-]', ''
            if ($norm -and $seenConnected.ContainsKey($norm)) { continue }
            if ($norm) { $seenConnected[$norm] = $true }
            $script:ConnNames += $cname
            $script:ConnCats  += 'web'
            $script:ConnTools += $ctc
            $script:ConnTags  += ''
            if ($norm) { $seenWebNorm[$norm] = $true }
        }

        # Add Google connectors that are authenticated
        foreach ($gn in ($googleState.Keys | Sort-Object)) {
            if ($googleState[$gn]) {
                $gnStr = [string]$gn
                $norm = ($gnStr.ToLower() -replace '[ _]', '-') -replace '[^a-z0-9\-]', ''
                if ($norm -and -not $seenWebNorm.ContainsKey($norm)) {
                    $script:ConnNames += $gnStr
                    $script:ConnCats  += 'web'
                    $script:ConnTools += '0'
                    $script:ConnTags  += ''
                    $seenWebNorm[$norm] = $true
                }
            }
        }

        # Add not-connected connectors from LevelDB (deduplicated, skip raw UUIDs)
        $seenNotConn = @{}
        foreach ($key in ($notConnectedUuids.Keys | Sort-Object)) {
            $cname = [string]$notConnectedUuids[$key]
            # Skip raw UUIDs — they're unresolved multi-org duplicates
            if ($cname -match $uuidPattern) { continue }
            $norm = ($cname.ToLower() -replace '[ _]', '-') -replace '[^a-z0-9\-]', ''
            if ($norm -and ($seenWebNorm.ContainsKey($norm) -or $seenNotConn.ContainsKey($norm))) { continue }
            if ($norm) { $seenNotConn[$norm] = $true }
            $script:ConnNames += $cname
            $script:ConnCats  += 'not_connected'
            $script:ConnTools += '0'
            $script:ConnTags  += ''
        }

        # Expiration findings
        foreach ($expName in $expiredUuids) {
            Add-Finding 'INFO' 'Connectors' "Connector '$expName' has expired authentication" 'isConnected=true but expiration is in the past'
        }

    } else {
        # ── No connector data from LevelDB ──
        if ($levelDbError) {
            Add-Finding 'INFO' 'Connectors' 'LevelDB connector state unreadable (file locked or inaccessible)' 'No connector data available'
        }
    }

    # Not connected: combine external_plugins, marketplace, remote plugins, and Google
    $notConnected = @{}

    # From external_plugins directories
    foreach ($d in $epDirs) {
        $dn = if ($displayNames.ContainsKey($d.Name.ToLower())) { $displayNames[$d.Name.ToLower()] } else { $d.Name }
        $norm = ($dn.ToLower() -replace '[ _]', '-') -replace '[^a-z0-9\-]', ''
        if ($norm -and -not $seenWebNorm.ContainsKey($norm)) { $notConnected[$norm] = $dn }
    }

    # From remote_cowork_plugins manifest
    foreach ($sessDir in $script:SessionDirs) {
        $remoteDir = Join-Path $sessDir 'remote_cowork_plugins'
        if (-not (Test-Path -LiteralPath $remoteDir -PathType Container)) { continue }
        $mfPath = Join-Path $remoteDir 'manifest.json'
        $mfData = Read-SafeJson $mfPath
        if ($script:JsonError -or -not $mfData) { continue }
        if (-not $mfData.PSObject.Properties['plugins'] -or $mfData.plugins -isnot [array]) { continue }
        foreach ($rp in $mfData.plugins) {
            if (-not ($rp -is [PSCustomObject])) { continue }
            $rpid = Get-JsonProp $rp 'id'
            if (-not $rpid) { continue }
            $mcpPath = Join-Path (Join-Path $remoteDir $rpid) '.mcp.json'
            $mcpData = Read-SafeJson $mcpPath
            if ($script:JsonError -or -not $mcpData) { continue }
            if (-not $mcpData.PSObject.Properties['mcpServers']) { continue }
            $mcpData.mcpServers.PSObject.Properties | ForEach-Object {
                $sn = $_.Name
                $norm = ($sn.ToLower() -replace '[ _]', '-') -replace '[^a-z0-9\-]', ''
                if ($norm -and -not $seenWebNorm.ContainsKey($norm) -and -not $notConnected.ContainsKey($norm)) {
                    $notConnected[$norm] = $sn
                }
            }
        }
    }

    # Add unauthenticated Google connectors
    foreach ($gn in ($googleState.Keys | Sort-Object)) {
        if (-not $googleState[$gn]) {
            $gnStr = [string]$gn
            $norm = ($gnStr.ToLower() -replace '[ _]', '-') -replace '[^a-z0-9\-]', ''
            if ($norm -and -not $seenWebNorm.ContainsKey($norm) -and -not $notConnected.ContainsKey($norm)) {
                $notConnected[$norm] = $gnStr
            }
        }
    }

    foreach ($key in ($notConnected.Keys | Sort-Object)) {
        $script:ConnNames += [string]$notConnected[$key]
        $script:ConnCats  += 'not_connected'
        $script:ConnTools += '0'
        $script:ConnTags  += ''
    }

    # Desktop connectors from extensions
    for ($i = 0; $i -lt $script:ExtNames.Count; $i++) {
        $tags = ''
        if ($script:ExtSigneds[$i] -eq 'false') { $tags = 'unsigned' }
        $script:ConnNames += $script:ExtNames[$i]
        $script:ConnCats  += 'desktop'
        $tc = 0
        if ($script:ExtToolsStr[$i]) {
            $tc = ($script:ExtToolsStr[$i] -split ',').Count
        }
        $script:ConnTools += "$tc"
        $script:ConnTags  += $tags
    }

    # Desktop connectors from MCP servers
    for ($i = 0; $i -lt $script:McpNames.Count; $i++) {
        $script:ConnNames += $script:McpNames[$i]
        $script:ConnCats  += 'desktop'
        $script:ConnTools += '0'
        $script:ConnTags  += 'LOCAL DEV'
    }

    # Web connector findings
    $webCount = ($script:ConnCats | Where-Object { $_ -eq 'web' }).Count
    if ($webCount -gt 0) {
        $webNames = @()
        for ($i = 0; $i -lt $script:ConnCats.Count; $i++) {
            if ($script:ConnCats[$i] -eq 'web') { $webNames += $script:ConnNames[$i] }
        }
        Add-Finding 'INFO' 'Connectors' "$webCount web connector(s) authenticated: $($webNames -join ', ')"
    }

    # Egress findings
    if ($script:EgressUnrestricted) {
        Add-Finding 'WARN' 'Security' 'Cowork VM egress is UNRESTRICTED - all domains allowed' 'egressAllowedDomains=["*"]'
    } elseif ($script:EgressDomains) {
        Add-Finding 'INFO' 'Cowork Settings' 'Cowork VM egress restricted to specific domains' "egressAllowedDomains: $($script:EgressDomains)"
    }

    # Disabled MCP tools findings
    if ($script:DisabledMcpTools.Count -gt 0) {
        $dangerousDisabled = @()
        foreach ($tk in $script:DisabledMcpTools) {
            if ($tk -match 'execute_javascript|write_file|edit_file|run_command') {
                $dangerousDisabled += $tk
            }
        }
        $detail = ''
        if ($dangerousDisabled.Count -gt 0) { $detail = "Includes dangerous tools: $($dangerousDisabled -join ', ')" }
        Add-Finding 'INFO' 'Cowork Settings' "$($script:DisabledMcpTools.Count) MCP tool(s) explicitly disabled" $detail
    }

    # Dispatch findings
    if ($script:DispatchActive) {
        Add-Finding 'WARN' 'Cowork Settings' 'Dispatch is actively ACCEPTING tasks - phone is remotely triggering desktop tasks' "hostLoopMode=true ($($script:DispatchSessionCount) session(s))"
    }
}

# ============================================================================
# 10. Collect-Skills
# ============================================================================
function Collect-Skills {
    param([string]$HomeDir)
    $seenSkills = @{}

    # Helper: add skill with dedup
    function Add-Skill {
        param([string]$Name, [string]$Desc, [string]$Source, [string]$Plugin, [string]$Path)
        if ($seenSkills.ContainsKey($Name)) { return }
        $seenSkills[$Name] = $true
        $script:SkNames   += $Name
        $script:SkDescs   += $Desc
        $script:SkSrcs    += $Source
        $script:SkPlugins += $Plugin
        $script:SkPaths   += $Path
    }

    # Helper: scan a directory of skill subdirectories for SKILL.md files
    function Add-SkillsFromDir {
        param([string]$Dir, [string]$Source, [string]$Plugin = '', [bool]$Dedup = $true)
        if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return }
        Get-ChildItem -LiteralPath $Dir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $skillMd = Join-Path $_.FullName 'SKILL.md'
            if (Test-Path -LiteralPath $skillMd -PathType Leaf) {
                Parse-SkillFrontmatter $skillMd
                $sn = if ($script:SkillFmName) { $script:SkillFmName } else { $_.Name }
                if ($Dedup) {
                    Add-Skill $sn $script:SkillFmDesc $Source $Plugin $skillMd
                } else {
                    $script:SkNames   += $sn
                    $script:SkDescs   += $script:SkillFmDesc
                    $script:SkSrcs    += $Source
                    $script:SkPlugins += $Plugin
                    $script:SkPaths   += $skillMd
                }
            }
        }
    }

    # 1. Scheduled task skills: ~/Documents/Claude/Scheduled/*/SKILL.md
    Add-SkillsFromDir (Join-Path $HomeDir 'DocumentsClaudeScheduled') 'user'

    # 2. Skills-plugin: local-agent-mode-sessions/skills-plugin/<id>/<id>/skills/<skill>/SKILL.md
    $spBase = Join-Path $env:APPDATA 'Claude\local-agent-mode-sessions\skills-plugin'
    if (Test-Path -LiteralPath $spBase -PathType Container) {
        Get-ChildItem -LiteralPath $spBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Add-SkillsFromDir (Join-Path $_.FullName 'skills') 'user'
            }
        }
    }

    # 3. Alt skills dir: ~/.skills/skills/*/SKILL.md
    Add-SkillsFromDir (Join-Path $HomeDir '.skillsskills') 'user'

    # 4. Claude Code user skills: ~/.claude/skills/*/SKILL.md
    Add-SkillsFromDir (Join-Path $HomeDir '.claudeskills') 'user'

    # 5. CC marketplace plugin skills: ~/.claude/plugins/marketplaces/<mp>/{plugins,external_plugins}/<plugin>/skills/<skill>/SKILL.md
    $ccMp = Join-Path $HomeDir '.claude\plugins\marketplaces'
    if (Test-Path -LiteralPath $ccMp -PathType Container) {
        Get-ChildItem -LiteralPath $ccMp -Recurse -Filter 'SKILL.md' -File -ErrorAction SilentlyContinue | ForEach-Object {
            $smd = $_.FullName
            $skParent = Split-Path $smd -Parent
            $skName = Split-Path $skParent -Leaf
            # Walk up to find plugin name: .../plugins/<plugin>/skills/<skill>/SKILL.md
            $skillsParent = Split-Path $skParent -Parent  # skills dir
            $pluginParent = Split-Path $skillsParent -Parent  # plugin dir
            $pluginName = Split-Path $pluginParent -Leaf
            Parse-SkillFrontmatter $smd
            $sn = if ($script:SkillFmName) { $script:SkillFmName } else { $skName }
            Add-Skill $sn $script:SkillFmDesc 'plugin' $pluginName $smd
        }
    }

    # 6. Session-scoped skills
    foreach ($sessDir in $script:SessionDirs) {
        # Remote plugin skills
        $remoteDir = Join-Path $sessDir 'remote_cowork_plugins'
        if (Test-Path -LiteralPath $remoteDir -PathType Container) {
            Get-ChildItem -LiteralPath $remoteDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'manifest.json' } | ForEach-Object {
                $pdir = $_.FullName
                $pluginName = $_.Name
                $pjPath = Join-Path $pdir '.claude-pluginplugin.json'
                $pjData = Read-SafeJson $pjPath
                $pjName = if (-not $script:JsonError -and $pjData) { Get-JsonProp $pjData 'name' } else { '' }
                if ($pjName) { $pluginName = $pjName }
                # Remote plugin skills are not deduped (different source)
                Add-SkillsFromDir (Join-Path $pdir 'skills') 'plugin' $pluginName $false
            }
        }

        # Cached plugin skills
        $cacheBase = Join-Path $sessDir 'cowork_pluginsche'
        if (Test-Path -LiteralPath $cacheBase -PathType Container) {
            Get-ChildItem -LiteralPath $cacheBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $cpd = $_.FullName
                    # Latest version directory
                    $verDirs = @(Get-ChildItem -LiteralPath $cpd -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                    if ($verDirs.Count -eq 0) { return }
                    $latest = $verDirs[0].FullName
                    $pluginName = Split-Path $cpd -Leaf
                    $pjPath = Join-Path $latest '.claude-pluginplugin.json'
                    $pjData = Read-SafeJson $pjPath
                    $pjName = if (-not $script:JsonError -and $pjData) { Get-JsonProp $pjData 'name' } else { '' }
                    if ($pjName) { $pluginName = $pjName }
                    Add-SkillsFromDir (Join-Path $latest 'skills') 'plugin' $pluginName $false
                }
            }
        }

        # Session-local user skills: local_<session>/.claude/skills/<skill>/SKILL.md
        Get-ChildItem -LiteralPath $sessDir -Directory -Filter 'local_*' -ErrorAction SilentlyContinue | ForEach-Object {
            Add-SkillsFromDir (Join-Path $_.FullName '.claudeskills') 'user'
        }
    }
}

# ============================================================================
# 11. Collect-ScheduledTasks
# ============================================================================
function Collect-ScheduledTasks {
    foreach ($sessDir in $script:SessionDirs) {
        $tf = Join-Path $sessDir 'scheduled-tasks.json'
        $data = Read-SafeJson $tf
        if ($script:JsonError -or -not $data) { continue }

        # Normalize to array
        $tasksJson = @()
        if ($data -is [array]) {
            $tasksJson = $data
        } elseif ($data -is [PSCustomObject]) {
            if ($data.PSObject.Properties['scheduledTasks'] -and $data.scheduledTasks -is [array]) {
                $tasksJson = $data.scheduledTasks
            } elseif ($data.PSObject.Properties['tasks'] -and $data.tasks -is [array]) {
                $tasksJson = $data.tasks
            } else {
                $tasksJson = @($data)
            }
        }

        foreach ($td in $tasksJson) {
            if (-not ($td -is [PSCustomObject])) { continue }
            $tid     = Get-JsonProp $td 'id'
            if (-not $tid) { $tid = Get-JsonProp $td 'taskId' 'unknown' }
            $tcron   = Get-JsonProp $td 'cronExpression'
            if (-not $tcron) { $tcron = Get-JsonProp $td 'cron' }
            $tenabled = Get-JsonProp $td 'enabled' 'true'
            $tfpath   = Get-JsonProp $td 'filePath'
            if (-not $tfpath) { $tfpath = Get-JsonProp $td 'skillPath' }

            $tcronEng = ''
            if ($tcron) { $tcronEng = ConvertTo-CronEnglish $tcron }

            # Validate filePath: must not be UNC and must be under expected directories
            $_claudeDir = Join-Path (Join-Path $script:HomeDir "AppData\Roaming") $script:CLAUDE_DESKTOP_DIR
            $_docsScheduled = Join-Path $script:HomeDir "Documents\Claude\Scheduled"
            $_claudeCode = Join-Path $script:HomeDir ".claude"
            $_skillsDir = Join-Path $script:HomeDir ".skills"
            $tfpathSafe = $false
            if ($tfpath -and -not $tfpath.StartsWith('\\') -and
                ($tfpath.StartsWith($_claudeDir, [StringComparison]::OrdinalIgnoreCase) -or
                 $tfpath.StartsWith($_docsScheduled, [StringComparison]::OrdinalIgnoreCase) -or
                 $tfpath.StartsWith($_claudeCode, [StringComparison]::OrdinalIgnoreCase) -or
                 $tfpath.StartsWith($_skillsDir, [StringComparison]::OrdinalIgnoreCase))) {
                $tfpathSafe = $true
            }

            $tsname = ''; $tsdesc = ''; $tprompt = ''
            if ($tfpath -and $tfpathSafe -and (Test-Path -LiteralPath $tfpath -PathType Leaf)) {
                try {
                    $stext = Get-Content -LiteralPath $tfpath -Raw -ErrorAction Stop
                } catch { $stext = '' }
                if ($stext) {
                    Parse-SkillFrontmatter $tfpath
                    $tsname = $script:SkillFmName
                    $tsdesc = $script:SkillFmDesc
                    # Extract body (after frontmatter) as prompt preview
                    $bodyLines = $stext -split "`n"
                    $inFm = $false; $bodyStart = 0
                    for ($li = 0; $li -lt $bodyLines.Count; $li++) {
                        if ($bodyLines[$li].Trim() -eq '---') {
                            if ($inFm) { $bodyStart = $li + 1; break }
                            else { $inFm = $true }
                        }
                    }
                    $body = ($bodyLines[$bodyStart..([Math]::Min($bodyStart + 19, $bodyLines.Count - 1))]) -join "`n"
                    if (-not $body) { $body = $stext }
                    if ($body.Length -gt 200) { $tprompt = $body.Substring(0, 200) } else { $tprompt = $body }
                }
            } elseif ($tfpath) {
                $tsname = '[SKILL FILE MISSING]'
            }

            $script:StIds      += $tid
            $script:StCrons    += $tcron
            $script:StCronEng  += $tcronEng
            $script:StEnableds += $tenabled
            $script:StFPaths   += $tfpath
            $script:StSNames   += $tsname
            $script:StSDescs   += $tsdesc
            $script:StPrompts  += $tprompt

            if ($tenabled -match '^[Tt]rue$') {
                $taskLabel = if ($tsname) { $tsname } else { $tid }
                Add-Finding 'WARN' 'Scheduled Tasks' "Active scheduled task: $taskLabel" "Cron: $tcron ($tcronEng)"
            }
        }
    }

    # Deferred scheduled-tasks-enabled findings (from Collect-DesktopSettings prefs)
    # Only WARN if the feature is enabled AND actual tasks exist; otherwise INFO.
    $hasActiveTasks = $script:StIds.Count -gt 0
    if ($script:CoworkPrefs['coworkScheduledTasksEnabled'] -match '^[Tt]rue$') {
        if ($hasActiveTasks) {
            Add-Finding 'WARN' 'Cowork Settings' 'Scheduled tasks ENABLED - autonomous task execution active' 'coworkScheduledTasksEnabled=true'
        } else {
            Add-Finding 'INFO' 'Cowork Settings' 'Scheduled tasks feature enabled but no tasks configured' 'coworkScheduledTasksEnabled=true'
        }
    }
    if ($script:CoworkPrefs['ccdScheduledTasksEnabled'] -match '^[Tt]rue$') {
        if ($hasActiveTasks) {
            Add-Finding 'WARN' 'Cowork Settings' 'Code Desktop scheduled tasks ENABLED' 'ccdScheduledTasksEnabled=true'
        } else {
            Add-Finding 'INFO' 'Cowork Settings' 'Code Desktop scheduled tasks feature enabled but no tasks configured' 'ccdScheduledTasksEnabled=true'
        }
    }
}

# ============================================================================
# 12. Collect-Blocklist
# ============================================================================
function Collect-Blocklist {
    param([string]$ClaudeDir)
    $blPath = Join-Path $ClaudeDir 'extensions-blocklist.json'
    $data = Read-SafeJson $blPath
    if ($script:JsonError) {
        $script:BlocklistStatus = $script:JsonError
        return
    }
    if (-not $data) {
        $script:BlocklistStatus = 'ABSENT'
        return
    }

    $total = 0
    if ($data -is [array]) {
        foreach ($item in $data) {
            if ($item -is [PSCustomObject] -and $item.PSObject.Properties['entries'] -and $item.entries -is [array]) {
                $total += $item.entries.Count
            } else {
                $total++
            }
        }
    } elseif ($data -is [PSCustomObject]) {
        $entriesJson = $null
        if ($data.PSObject.Properties['blocklist'])  { $entriesJson = $data.blocklist }
        elseif ($data.PSObject.Properties['extensions']) { $entriesJson = $data.extensions }
        else { $entriesJson = $data }

        if ($entriesJson -is [array]) {
            foreach ($item in $entriesJson) {
                if ($item -is [PSCustomObject] -and $item.PSObject.Properties['entries'] -and $item.entries -is [array]) {
                    $total += $item.entries.Count
                } else {
                    $total++
                }
            }
        } elseif ($entriesJson -is [PSCustomObject]) {
            $total = @($entriesJson.PSObject.Properties).Count
        }
    }

    $script:BlocklistEntries = $total
    if ($total -eq 0) {
        Add-Finding 'WARN' 'Security' 'Extension blocklist is empty - no governance controls'
        $script:BlocklistStatus = 'EMPTY'
    } else {
        $script:BlocklistStatus = "$total entries"
    }
}

# ============================================================================
# 13. Collect-ClaudeCodeSettings
# ============================================================================
function Collect-ClaudeCodeSettings {
    param([string]$HomeDir)
    $settingsPath = Join-Path $HomeDir '.claude\settings.json'
    $data = Read-SafeJson $settingsPath
    if ($script:JsonError -or -not $data) { return }
    $script:ClaudeCodeJson = $data

    # Permissions
    if ($data.PSObject.Properties['permissions'] -and $data.permissions -and $data.permissions.PSObject.Properties['allow']) {
        $allow = $data.permissions.allow
        if ($allow -is [array] -and $allow.Count -gt 0) {
            Add-Finding 'INFO' 'Claude Code' "Permissions granted: $($allow -join ', ')"
        } elseif ($allow -is [string] -and $allow) {
            Add-Finding 'INFO' 'Claude Code' "Permissions granted: $allow"
        }
    }
}

# ============================================================================
# 14. Collect-ClaudeCodeManagedPolicy (Windows admin-deployed policy + MCP)
# ============================================================================
# Reads the system-wide Claude Code policy files written by enterprise admins:
#   - managed-mcp.json       : MCP servers pushed to all users
#   - managed-settings.json  : policy / setting overrides
#   - managed-settings.d\*.json : drop-in policy fragments (new path only)
#
# Claude Code v2.1.75 dropped support for the legacy %PROGRAMDATA%\ClaudeCode
# location and now only honors %PROGRAMFILES%\ClaudeCode. We scan both so we
# can warn when stale files remain in the legacy location after the upgrade.
function Collect-ClaudeCodeManagedPolicy {
    $programFiles = if ($env:ProgramFiles) { $env:ProgramFiles } else { 'C:\Program Files' }
    $programData  = if ($env:ProgramData)  { $env:ProgramData }  else { 'C:\ProgramData' }

    $newRoot    = Join-Path $programFiles 'ClaudeCode'
    $legacyRoot = Join-Path $programData  'ClaudeCode'

    # Single helper that processes one managed-mcp.json or managed-settings.json file.
    function _process_managed_file {
        param(
            [string]$Path,
            [string]$Kind,    # 'mcp' or 'settings'
            [string]$Source   # 'programfiles' or 'programdata'
        )
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

        $script:ManagedPolicyFiles.Add($Path)
        if ($Source -eq 'programdata') {
            $script:ManagedPolicyLegacy.Add($Path)
            $script:ManagedSettingsLegacyHit = $true
        }

        $data = Read-SafeJson $Path
        if ($script:JsonError) {
            if ($script:JsonError -ne 'ABSENT') {
                Add-Finding 'INFO' 'Managed Policy' "$(Split-Path $Path -Leaf): [$($script:JsonError)]" $Path
            }
            return
        }
        if (-not $data) { return }

        if ($Kind -eq 'mcp') {
            $mcpJson = $null
            if ($data.PSObject.Properties['mcpServers']) { $mcpJson = $data.mcpServers }
            if (-not $mcpJson) { return }

            $count = 0
            $mcpJson.PSObject.Properties | ForEach-Object {
                $sname = $_.Name
                $srv   = $_.Value

                $cmd = Get-JsonProp $srv 'command' '[unknown]'

                $argsArr = @()
                if ($srv.PSObject.Properties['args'] -and $srv.args -is [array]) {
                    $argsArr = $srv.args | ForEach-Object { Redact-Arg "$_" }
                }
                $argsStr = $argsArr -join ' '

                $envKeys = '-'
                if ($srv.PSObject.Properties['env'] -and $srv.env) {
                    $keys = @($srv.env.PSObject.Properties | ForEach-Object { $_.Name })
                    if ($keys.Count -gt 0) { $envKeys = $keys -join ', ' }
                }

                $script:ManagedMcpNames    += $sname
                $script:ManagedMcpCmds     += $cmd
                $script:ManagedMcpArgsStr  += $argsStr
                $script:ManagedMcpEnvKeys  += $envKeys
                $script:ManagedMcpSources  += $Source
                $count++
            }

            if ($count -gt 0) {
                $sev = if ($Source -eq 'programdata') { 'WARN' } else { 'INFO' }
                $msg = "$count managed MCP server(s) deployed via $Path"
                Add-Finding $sev 'Managed Policy' $msg
            }
        }
        elseif ($Kind -eq 'settings') {
            $keys = @($data.PSObject.Properties | ForEach-Object { $_.Name })
            foreach ($k in $keys) {
                if ($script:ManagedSettingsKeys -notcontains $k) {
                    $script:ManagedSettingsKeys += $k
                }
            }
            if ($keys.Count -gt 0) {
                $sev = if ($Source -eq 'programdata') { 'WARN' } else { 'INFO' }
                Add-Finding $sev 'Managed Policy' "Managed settings present in $Path" "Top-level keys: $($keys -join ', ')"
            }
        }
    }

    # Current location (v2.1.75+)
    _process_managed_file -Path (Join-Path $newRoot 'managed-mcp.json')      -Kind 'mcp'      -Source 'programfiles'
    _process_managed_file -Path (Join-Path $newRoot 'managed-settings.json') -Kind 'settings' -Source 'programfiles'

    # Drop-in policy fragments (new location only - systemd-style merge)
    $dropInDir = Join-Path $newRoot 'managed-settings.d'
    if (Test-Path -LiteralPath $dropInDir -PathType Container) {
        $fragments = @(Get-ChildItem -LiteralPath $dropInDir -Filter '*.json' -File -ErrorAction SilentlyContinue |
                       Sort-Object Name)
        foreach ($f in $fragments) {
            _process_managed_file -Path $f.FullName -Kind 'settings' -Source 'programfiles'
        }
        if ($fragments.Count -gt 0) {
            Add-Finding 'INFO' 'Managed Policy' "$($fragments.Count) policy fragment(s) in managed-settings.d\" $dropInDir
        }
    }

    # Legacy location (deprecated as of Claude Code v2.1.75 - no longer honored)
    _process_managed_file -Path (Join-Path $legacyRoot 'managed-mcp.json')      -Kind 'mcp'      -Source 'programdata'
    _process_managed_file -Path (Join-Path $legacyRoot 'managed-settings.json') -Kind 'settings' -Source 'programdata'

    if ($script:ManagedSettingsLegacyHit) {
        $detail = "Files remain in legacy location: $($script:ManagedPolicyLegacy -join '; '). Migrate to $newRoot\."
        Add-Finding 'WARN' 'Managed Policy' 'Managed policy files present in legacy %PROGRAMDATA% path - no longer honored as of Claude Code v2.1.75' $detail
    }
}

# ============================================================================
# 15. Collect-Runtime (Windows-specific)
# ============================================================================
function Collect-Runtime {
    param([string]$ClaudeDir, [string]$HomeDir)

    # Claude/Electron processes
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match 'claude|electron'
        }
        if ($procs -and $procs.Count -gt 0) {
            $procInfo = ($procs | ForEach-Object { "$($_.Id) $($_.ProcessName)" }) -join "`n"
            $script:RuntimeInfo['claude_processes'] = $procInfo
            Add-Finding 'INFO' 'Runtime' "Claude is running ($($procs.Count) processes)"
        }
    } catch {}

    # Windows Scheduled Tasks (Claude-related)
    try {
        $winTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -match '(?i)claude' -or $_.TaskPath -match '(?i)claude'
        }
        if ($winTasks -and @($winTasks).Count -gt 0) {
            $taskNames = ($winTasks | ForEach-Object { $_.TaskName }) -join ', '
            $script:RuntimeInfo['scheduled_tasks'] = $taskNames
            Add-Finding 'WARN' 'Runtime' "Windows Scheduled Task(s) found: $taskNames"
        }
    } catch {}

    # Sleep prevention assertions (powercfg)
    try {
        $powercfg = & "$env:SystemRoot\System32\powercfg.exe" /requests 2>$null
        if ($powercfg) {
            $script:RuntimeInfo['powercfg_requests'] = ($powercfg -join "`n")
            $powercfg | ForEach-Object {
                if ($_ -match '(?i)(claude|electron)') {
                    Add-Finding 'WARN' 'Runtime' 'Sleep prevention assertion by Claude/Electron' $_.Trim()
                }
            }
        }
    } catch {}

    # Claude in Windows Startup (shell:startup)
    try {
        $startupDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
        if (Test-Path -LiteralPath $startupDir -PathType Container) {
            $claudeStartup = Get-ChildItem -LiteralPath $startupDir -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match '(?i)claude'
            }
            if ($claudeStartup) {
                $startupNames = ($claudeStartup | ForEach-Object { $_.Name }) -join ', '
                $script:RuntimeInfo['startup_entries'] = $startupNames
                Add-Finding 'WARN' 'Runtime' "Claude found in Windows Startup: $startupNames"
            }
        }
    } catch {}

    # Registry Run keys (HKCU and HKLM)
    try {
        $runKeys = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($rk in $runKeys) {
            if (-not (Test-Path -LiteralPath $rk)) { continue }
            try {
                $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and "$($_.Value)" -match '(?i)claude' } | ForEach-Object {
                        $script:RuntimeInfo["registry_run_$($_.Name)"] = "$($_.Value)"
                        Add-Finding 'WARN' 'Runtime' "Claude in registry Run key: $rk\$($_.Name)" "$($_.Value)"
                    }
                }
            } catch {}
        }
    } catch {}

    # Windows services (Claude-related)
    try {
        $claudeSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '(?i)claude' -or $_.DisplayName -match '(?i)claude'
        }
        if ($claudeSvcs -and @($claudeSvcs).Count -gt 0) {
            $svcInfo = ($claudeSvcs | ForEach-Object { "$($_.Name) ($($_.Status))" }) -join ', '
            $script:RuntimeInfo['services'] = $svcInfo
            Add-Finding 'INFO' 'Runtime' "Claude-related Windows service(s): $svcInfo"
        }
    } catch {}

    # Debug/logs directory size
    $debugDir = Join-Path $ClaudeDir 'debug'
    $logsDir  = Join-Path $ClaudeDir 'logs'
    foreach ($checkDir in @($debugDir, $logsDir)) {
        if (Test-Path -LiteralPath $checkDir -PathType Container) {
            try {
                $sizeBytes = (Get-ChildItem -LiteralPath $checkDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                if (-not $sizeBytes) { $sizeBytes = 0 }
                $label = Split-Path $checkDir -Leaf
                $script:RuntimeInfo["${label}_dir_size"] = (Format-Bytes $sizeBytes)
                if ($sizeBytes -gt 104857600) {  # 100 MB
                    Add-Finding 'WARN' 'Runtime' "$label directory is large: $(Format-Bytes $sizeBytes)" "$checkDir"
                }
            } catch {}
        }
    }

    # Device ID from ant-did file
    $antDidFile = Join-Path $ClaudeDir 'ant-did'
    if (Test-Path -LiteralPath $antDidFile -PathType Leaf) {
        try {
            $antDid = (Get-Content -LiteralPath $antDidFile -Raw -ErrorAction Stop).Trim()
            if ($antDid -and -not $script:RuntimeInfo.ContainsKey('ant_did')) {
                $script:RuntimeInfo['ant_did'] = $antDid
            }
        } catch {}
    }
}

# ============================================================================

# ── Recommendations & Renderers ─────────────────────────────────────────────

# ── Recommendations ──────────────────────────────────────────────────────────

function Build-Recommendations {
    $script:Recommendations = [System.Collections.Generic.List[string]]::new()

    # Keep Awake
    if ($script:DesktopPrefs['keepAwakeEnabled'] -eq 'true') {
        $script:Recommendations.Add("Keep Awake is ON - prevents Windows from sleeping")
    }

    # Active scheduled tasks
    $activeCount = 0
    for ($i = 0; $i -lt $script:StEnableds.Count; $i++) {
        if ($script:StEnableds[$i] -eq 'true') { $activeCount++ }
    }
    if ($activeCount -gt 0) {
        $script:Recommendations.Add("$activeCount active scheduled task(s) - review purpose and prompts")
    }

    # Unsigned extensions
    $unsignedNames = @()
    for ($i = 0; $i -lt $script:ExtSigneds.Count; $i++) {
        if ($script:ExtSigneds[$i] -eq 'false') {
            $unsignedNames += $script:ExtNames[$i]
        }
    }
    if ($unsignedNames.Count -gt 0) {
        $script:Recommendations.Add("Unsigned extensions: $($unsignedNames -join ', ')")
    }

    # Dangerous tool extensions
    for ($i = 0; $i -lt $script:ExtDangerStr.Count; $i++) {
        if ($script:ExtDangerStr[$i]) {
            $dtools = $script:ExtDangerStr[$i] -replace ',', ', '
            $script:Recommendations.Add("Extension '$($script:ExtNames[$i])' has dangerous tools: $dtools")
        }
    }

    # MCP servers
    if ($script:McpNames.Count -gt 0) {
        $script:Recommendations.Add("$($script:McpNames.Count) MCP server(s) configured - verify each is expected")
    }

    # Allowlist disabled
    $alCount = 0
    for ($i = 0; $i -lt $script:FindingMsg.Count; $i++) {
        if ($script:FindingMsg[$i] -match '(?i)allowlist disabled') { $alCount++ }
    }
    if ($alCount -gt 0) {
        $script:Recommendations.Add("Extension allowlist disabled ($alCount org scope(s))")
    }

    # Web search
    if ($script:CoworkPrefs['coworkWebSearchEnabled'] -eq 'true') {
        $script:Recommendations.Add("Cowork web search enabled - autonomous internet access")
    }

    # Allow all browser actions
    if ($script:CoworkPrefs['allowAllBrowserActions'] -eq 'true') {
        $script:Recommendations.Add("Allow all browser actions enabled - Claude can browse any website without asking")
    }

    # Egress unrestricted
    if ($script:EgressUnrestricted -eq $true) {
        $script:Recommendations.Add("Cowork VM network egress is unrestricted - all domains reachable")
    }

    # Dispatch
    if ($script:DispatchActive -eq $true) {
        $script:Recommendations.Add("Dispatch is actively accepting tasks - mobile device is remotely triggering tasks on this desktop")
    }
    elseif ($script:DispatchBridgeEnabled -eq $true) {
        $script:Recommendations.Add("Dispatch bridge is configured - mobile device can dispatch tasks to this desktop (files, connectors, computer use)")
    }

    # Plugin hooks
    if ($script:HookPlugins.Count -gt 0) {
        $script:Recommendations.Add("$($script:HookPlugins.Count) plugin hook(s) execute commands on lifecycle events - review for data exfiltration risk")
    }

    # Remote plugins
    $remoteNames = @()
    for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
        if ($script:PlgSrcs[$i] -eq 'remote') { $remoteNames += $script:PlgNames[$i] }
    }
    if ($remoteNames.Count -gt 0) {
        $script:Recommendations.Add("Remote plugins: $($remoteNames -join ', ')")
    }

    # Cached plugins
    $cachedNames = @()
    for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
        if ($script:PlgSrcs[$i] -eq 'cached') { $cachedNames += $script:PlgNames[$i] }
    }
    if ($cachedNames.Count -gt 0) {
        $script:Recommendations.Add("Cached (not installed) plugins: $($cachedNames -join ', ')")
    }

    # Web connectors
    $webConnNames = @()
    for ($i = 0; $i -lt $script:ConnCats.Count; $i++) {
        if ($script:ConnCats[$i] -eq 'web') { $webConnNames += $script:ConnNames[$i] }
    }
    if ($webConnNames.Count -gt 0) {
        $script:Recommendations.Add("$($webConnNames.Count) web connector(s) authenticated: $($webConnNames -join ', ')")
    }
}

# ── ASCII Renderer ───────────────────────────────────────────────────────────

function Render-Ascii {
    param([bool]$quiet = $false)

    # Color detection
    $script:UseColor = -not [Console]::IsOutputRedirected
    $ESC = [char]0x1B

    # Color helper functions
    function _c([string]$code, [string]$text) {
        if ($script:UseColor) { return "$ESC[${code}m${text}$ESC[0m" } else { return $text }
    }
    function _red([string]$t)    { return (_c "1;31" $t) }
    function _yellow([string]$t) { return (_c "33" $t) }
    function _cyan([string]$t)   { return (_c "36" $t) }
    function _green([string]$t)  { return (_c "32" $t) }
    function _bold([string]$t)   { return (_c "1" $t) }
    function _dim([string]$t)    { return (_c "2" $t) }

    function _sev_color([string]$sev, [string]$text) {
        if (-not $text) { $text = $sev }
        switch ($sev) {
            'CRITICAL' { return (_red $text) }
            'WARN'     { return (_yellow $text) }
            'REVIEW'   { return (_yellow $text) }
            'INFO'     { return (_cyan $text) }
            'OK'       { return (_green $text) }
            'PASS'     { return (_green $text) }
            default    { return $text }
        }
    }

    function _on_off([string]$val) {
        switch ($val) {
            'true'       { return (_yellow "ON") }
            'false'      { return (_green "OFF") }
            'configured' { return (_yellow "CONFIGURED") }
            ''           { return (_dim "-") }
            default      { return $val }
        }
    }

    function _strip_ansi([string]$s) {
        return [regex]::Replace($s, "$([char]0x1B)\[[0-9;]*m", '')
    }

    function _section_hdr([string]$title, [int]$w = 66) {
        $prefix = ([string][char]0x2500) * 4 + " $title "
        $remaining = $w - $prefix.Length
        if ($remaining -lt 0) { $remaining = 0 }
        Write-Host ($prefix + (([string][char]0x2500) * $remaining))
    }

    function Ascii-Table {
        param([string[]]$headers, [string[][]]$rows, [int[]]$widths)
        $ncols = $headers.Count

        # Top border
        $hLine = [string][char]0x2500
        $top = [string][char]0x250C
        for ($i = 0; $i -lt $ncols; $i++) {
            $top += ($hLine * ($widths[$i] + 2))
            if ($i -lt $ncols - 1) { $top += [char]0x252C }
        }
        $top += [char]0x2510
        Write-Host $top

        # Header row
        $vLine = [string][char]0x2502
        $hdr = $vLine
        for ($i = 0; $i -lt $ncols; $i++) {
            $h = $headers[$i]
            if ($h.Length -gt $widths[$i]) { $h = $h.Substring(0, $widths[$i]) }
            $hdr += " " + $h.PadRight($widths[$i]) + " " + $vLine
        }
        Write-Host $hdr

        # Separator
        $sep = [string][char]0x251C
        for ($i = 0; $i -lt $ncols; $i++) {
            $sep += ($hLine * ($widths[$i] + 2))
            if ($i -lt $ncols - 1) { $sep += [char]0x253C }
        }
        $sep += [char]0x2524
        Write-Host $sep

        # Data rows
        foreach ($row in $rows) {
            $rline = $vLine
            for ($i = 0; $i -lt $ncols; $i++) {
                $val = if ($i -lt $row.Count) { $row[$i] } else { '' }
                $plain = _strip_ansi $val
                if ($plain.Length -gt $widths[$i]) { $plain = $plain.Substring(0, $widths[$i]) }
                $rline += " " + $plain.PadRight($widths[$i]) + " " + $vLine
            }
            Write-Host $rline
        }

        # Bottom border
        $bot = [string][char]0x2514
        for ($i = 0; $i -lt $ncols; $i++) {
            $bot += ($hLine * ($widths[$i] + 2))
            if ($i -lt $ncols - 1) { $bot += [char]0x2534 }
        }
        $bot += [char]0x2518
        Write-Host $bot
    }

    # ── Banner ──
    $orange = "$ESC[38;5;208m"
    $gray   = "$ESC[38;5;243m"
    $reset  = "$ESC[0m"
    $w = 66

    if ($script:UseColor) { Write-Host "" ; Write-Host $orange -NoNewline }
    Write-Host @"
  ██████ ██       █████  ██    ██ ██████  ██ ████████       ███████ ███████  ██████
 ██      ██      ██   ██ ██    ██ ██   ██ ██    ██          ██      ██      ██
 ██      ██      ███████ ██    ██ ██   ██ ██    ██    █████ ███████ █████   ██
 ██      ██      ██   ██ ██    ██ ██   ██ ██    ██               ██ ██      ██
  ██████ ███████ ██   ██  ██████  ██████  ██    ██          ███████ ███████  ██████
"@
    if ($script:UseColor) {
        Write-Host "${gray}  // Claude security auditing CLI - skills, plugins & misconfiguration detection${reset}"
    } else {
        Write-Host "  // Claude security auditing CLI - skills, plugins & misconfiguration detection"
    }
    Write-Host ""

    # Info box
    $dLine = [string][char]0x2550
    $topBar = [string][char]0x2554 + ($dLine * $w) + [char]0x2557
    $botBar = [string][char]0x255A + ($dLine * $w) + [char]0x255D
    Write-Host $topBar

    $tsLen = $script:Timestamp.Length
    $lpad = [math]::Floor(($w - $tsLen) / 2)
    $rpad = $w - $tsLen - $lpad
    Write-Host ("$([char]0x2551)" + (' ' * $lpad) + $script:Timestamp + (' ' * $rpad) + "$([char]0x2551)")

    $info = "Host: $($script:HostnameVal) | User: $($script:AuditUser)"
    $lpad = [math]::Floor(($w - $info.Length) / 2)
    $rpad = $w - $info.Length - $lpad
    Write-Host ("$([char]0x2551)" + (' ' * $lpad) + $info + (' ' * $rpad) + "$([char]0x2551)")
    Write-Host $botBar
    Write-Host ""

    # ── Summary ──
    _section_hdr "SUMMARY"
    $nInst = $script:CountPluginInstalled; $nRem = $script:CountPluginRemote; $nCach = $script:CountPluginCached
    $nWeb = $script:CountConnWeb; $nNc = $script:CountConnNotConn
    $warnC = $script:WarnCount
    $revC = ($script:FindingSev | Where-Object { $_ -eq 'REVIEW' }).Count
    Write-Host "  Scheduled tasks: $($script:StIds.Count)  |  MCP servers: $($script:McpNames.Count)  |  Extensions: $($script:ExtNames.Count)"
    Write-Host "  Plugins: $nInst installed, $nRem remote, $nCach cached  |  Connectors: $nWeb web, $nNc not connected"
    Write-Host "  Skills: $($script:SkNames.Count)  |  Findings: $warnC warnings, $revC items to review"
    if ($script:WsUuids.Count -gt 0) {
        $dispState = if ($script:DispatchBridgeEnabled -eq $true) { "CONFIGURED" } else { "off" }
        Write-Host "  Workspaces: $($script:WsUuids.Count)  |  Dispatch bridge: $dispState"
    }
    Write-Host ""

    # ── Workspaces ──
    if ($script:WsUuids.Count -gt 1 -and -not $quiet) {
        _section_hdr "WORKSPACES"
        $wsRows = @()
        for ($i = 0; $i -lt $script:WsUuids.Count; $i++) {
            $uidShort = (Get-TruncatedString $script:WsUuids[$i] 11)
            $indicators = @()
            if ($script:WsDxtAllowlists[$i] -eq 'true')       { $indicators += "DXT-managed" }
            if ($script:WsHasRemotePlugins[$i] -eq 'true')    { $indicators += "org-plugins" }
            if ($script:WsBridgeActive[$i] -eq 'true')        { $indicators += "dispatch-bridge" }
            $indStr = if ($indicators.Count -gt 0) { $indicators -join ", " } else { "-" }
            $acct  = if ($script:WsAcctNames[$i]) { $script:WsAcctNames[$i] } else { "-" }
            $email = if ($script:WsEmails[$i])    { $script:WsEmails[$i] }    else { "-" }
            $wsRows += ,@($uidShort, $acct, $email, "$($script:WsSessionCounts[$i])", $indStr)
        }
        Ascii-Table -headers @("User UUID","Account","Email","Sessions","Indicators") -rows $wsRows -widths @(14,10,26,8,24)
        Write-Host ""
    }

    # ── Desktop Settings ──
    $kae = if ($script:DesktopPrefs['keepAwakeEnabled']) { $script:DesktopPrefs['keepAwakeEnabled'] } else { 'false' }
    if (-not $quiet) {
        _section_hdr "DESKTOP SETTINGS"
        $line = "  keepAwakeEnabled:              $(_on_off $kae)"
        if ($kae -eq 'true') { $line += "   ! Prevents Windows from sleeping" }
        Write-Host $line
        Write-Host "  menuBarEnabled:                $(_on_off $(if ($script:DesktopPrefs['menuBarEnabled']) { $script:DesktopPrefs['menuBarEnabled'] } else { 'false' }))"
        Write-Host "  sidebarMode:                   $(if ($script:DesktopPrefs['sidebarMode']) { $script:DesktopPrefs['sidebarMode'] } else { (_dim '-') })"
        Write-Host "  quickEntryShortcut:            $(if ($script:DesktopPrefs['quickEntryShortcut']) { $script:DesktopPrefs['quickEntryShortcut'] } else { (_dim '-') })"
        Write-Host ""
    }
    elseif ($kae -eq 'true') {
        _section_hdr "DESKTOP SETTINGS"
        Write-Host "  keepAwakeEnabled:              $(_on_off $kae)   ! Prevents Windows from sleeping"
        Write-Host ""
    }

    # ── Cowork Settings ──
    $cst = if ($script:CoworkPrefs['coworkScheduledTasksEnabled']) { $script:CoworkPrefs['coworkScheduledTasksEnabled'] } else { 'false' }
    $ccd = if ($script:CoworkPrefs['ccdScheduledTasksEnabled'])    { $script:CoworkPrefs['ccdScheduledTasksEnabled'] }    else { 'false' }
    $cws = if ($script:CoworkPrefs['coworkWebSearchEnabled'])      { $script:CoworkPrefs['coworkWebSearchEnabled'] }      else { 'false' }
    $aba = if ($script:CoworkPrefs['allowAllBrowserActions'])      { $script:CoworkPrefs['allowAllBrowserActions'] }      else { 'false' }

    if (-not $quiet) {
        _section_hdr "COWORK SETTINGS"
        $line = "  scheduledTasksEnabled:         $(_on_off $cst)"
        if ($cst -eq 'true') { $line += "   ! Autonomous task execution" }
        Write-Host $line

        $line = "  ccdScheduledTasksEnabled:      $(_on_off $ccd)"
        if ($ccd -eq 'true') { $line += "   ! Code Desktop scheduled tasks" }
        Write-Host $line

        $line = "  webSearchEnabled:              $(_on_off $cws)"
        if ($cws -eq 'true') { $line += "   ! Autonomous internet access" }
        Write-Host $line

        $line = "  allowAllBrowserActions:        $(_on_off $aba)"
        if ($aba -eq 'true') { $line += "   ! Browse any website without asking" }
        Write-Host $line

        $dispatchState = 'false'
        if ($script:DispatchBridgeEnabled -eq $true) { $dispatchState = 'configured' }
        if ($script:DispatchActive -eq $true)        { $dispatchState = 'true' }
        $line = "  dispatch (mobile->desktop):    $(_on_off $dispatchState)"
        if ($script:DispatchActive -eq $true) {
            $line += "   ! Actively accepting dispatched tasks"
        } elseif ($script:DispatchBridgeEnabled -eq $true) {
            $line += "   ! Bridge configured - phone can dispatch tasks"
        }
        Write-Host $line

        $nm = if ($script:CoworkNetworkMode) { $script:CoworkNetworkMode } else { (_dim "-") }
        Write-Host "  networkMode:                   $nm"

        if ($script:EgressUnrestricted -eq $true) {
            Write-Host "  egressAllowedDomains:          $(_on_off 'true')   ! All domains reachable"
        } elseif ($script:EgressDomains) {
            Write-Host "  egressAllowedDomains:          $(_dim 'restricted')"
        } else {
            Write-Host "  egressAllowedDomains:          $(_dim '-')"
        }

        if ($script:DisabledMcpTools.Count -gt 0) {
            Write-Host "  Disabled MCP tools:            $($script:DisabledMcpTools.Count) tool(s)"
        }
        if ($script:CoworkEnabledPlugins.Count -gt 0) {
            Write-Host "  Enabled plugins:               $($script:CoworkEnabledPlugins -join ', ')"
        }
        if ($script:CoworkMarketplacesJson -and $script:CoworkMarketplacesJson.Count -gt 0) {
            foreach ($mk in $script:CoworkMarketplacesJson.Keys) {
                try {
                    $mpObj = $script:CoworkMarketplacesJson[$mk] | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $st = if ($mpObj.source.source) { $mpObj.source.source } else { "?" }
                    $sr = if ($mpObj.source.repo) { $mpObj.source.repo } elseif ($mpObj.source.path) { $mpObj.source.path } else { "" }
                    Write-Host "  Marketplace source:            $mk ($st`: $sr)"
                } catch { }
            }
        }
        Write-Host ""
    }
    else {
        # Quiet mode: only show warnings
        $wi = @()
        if ($cst -eq 'true') { $wi += "  scheduledTasksEnabled:         $(_on_off $cst)   ! Autonomous task execution" }
        if ($ccd -eq 'true') { $wi += "  ccdScheduledTasksEnabled:      $(_on_off $ccd)   ! Code Desktop scheduled tasks" }
        if ($cws -eq 'true') { $wi += "  webSearchEnabled:              $(_on_off $cws)   ! Autonomous internet access" }
        if ($aba -eq 'true') { $wi += "  allowAllBrowserActions:        $(_on_off $aba)   ! Browse any website without asking" }
        if ($script:DispatchActive -eq $true) {
            $wi += "  dispatch (mobile->desktop):    $(_on_off 'true')   ! Actively accepting dispatched tasks"
        }
        if ($script:DispatchBridgeEnabled -eq $true -and $script:DispatchActive -ne $true) {
            $wi += "  dispatch (mobile->desktop):    $(_on_off 'configured')   ! Bridge configured - phone can dispatch tasks"
        }
        if ($script:EgressUnrestricted -eq $true) {
            $wi += "  egressAllowedDomains:          $(_on_off 'true')   ! All domains reachable"
        }
        if ($wi.Count -gt 0) {
            _section_hdr "COWORK SETTINGS"
            foreach ($w in $wi) { Write-Host $w }
            Write-Host ""
        }
    }

    # ── Plugin Hooks ──
    if ((-not $quiet) -or ($script:HookPlugins.Count -gt 0)) {
        if ($script:HookPlugins.Count -gt 0) {
            _section_hdr "PLUGIN HOOKS"
            $hookRows = @()
            for ($i = 0; $i -lt $script:HookPlugins.Count; $i++) {
                $hookRows += ,@(
                    (Get-TruncatedString $script:HookPlugins[$i] 24),
                    (Get-TruncatedString $script:HookEvents[$i] 18),
                    (Get-TruncatedString $script:HookCmds[$i] 48)
                )
            }
            Ascii-Table -headers @("Plugin","Event","Command") -rows $hookRows -widths @(24,18,48)
            Write-Host ""
        }
    }

    # ── MCP Servers ──
    if ((-not $quiet) -or ($script:McpNames.Count -gt 0)) {
        _section_hdr "MCP SERVERS"
        if ($script:McpNames.Count -gt 0) {
            $mcpRows = @()
            for ($i = 0; $i -lt $script:McpNames.Count; $i++) {
                $mcpRows += ,@(
                    (Get-TruncatedString $script:McpNames[$i] 26),
                    (Get-TruncatedString $script:McpCmds[$i] 30),
                    (Get-TruncatedString $script:McpArgsStr[$i] 16),
                    (Get-TruncatedString $script:McpEnvKeys[$i] 16)
                )
            }
            Ascii-Table -headers @("Server Name","Command","Args","Env Vars") -rows $mcpRows -widths @(26,30,16,16)
            Write-Host "  $(_yellow '[REVIEW]') MCP servers can execute arbitrary commands and access external services."
        } else {
            Write-Host "  $(_green 'No MCP servers configured.')"
        }
        Write-Host ""
    }

    # ── Plugins ──
    $hasPlg = ($nInst -gt 0 -or $nRem -gt 0 -or $nCach -gt 0)
    if ((-not $quiet) -or $hasPlg) {
        _section_hdr "PLUGINS"
        if ($nInst -gt 0) {
            Write-Host "  $(_bold 'Installed:')"
            $plgRows = @()
            for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
                if ($script:PlgSrcs[$i] -ne 'installed') { continue }
                $instDate = if ($script:PlgInstalledAts[$i] -and $script:PlgInstalledAts[$i].Length -ge 10) { $script:PlgInstalledAts[$i].Substring(0,10) } else { '-' }
                $plgRows += ,@(
                    (Get-TruncatedString $script:PlgNames[$i] 24),
                    (Get-TruncatedString $script:PlgVers[$i] 8),
                    (Get-TruncatedString $script:PlgMps[$i] 24),
                    (Get-TruncatedString $script:PlgScopes[$i] 6),
                    (Get-TruncatedString $instDate 24)
                )
            }
            Ascii-Table -headers @("Name","Version","Source","Scope","Installed") -rows $plgRows -widths @(24,8,24,6,24)
        }
        if ($nRem -gt 0) {
            Write-Host "  $(_bold 'Remote (org-deployed):')"
            $remRows = @()
            for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
                if ($script:PlgSrcs[$i] -ne 'remote') { continue }
                $remRows += ,@(
                    (Get-TruncatedString $script:PlgNames[$i] 16),
                    (Get-TruncatedString $script:PlgVers[$i] 8),
                    (Get-TruncatedString $script:PlgAuthors[$i] 12),
                    (Get-TruncatedString $script:PlgMps[$i] 24),
                    "$($script:PlgSkillCounts[$i])"
                )
            }
            Ascii-Table -headers @("Name","Version","Author","Marketplace","Skills") -rows $remRows -widths @(16,8,12,24,6)
        }
        if ($nCach -gt 0) {
            Write-Host "  $(_bold 'Cached (downloaded):')"
            for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
                if ($script:PlgSrcs[$i] -ne 'cached') { continue }
                Write-Host "    $($script:PlgNames[$i]) v$($script:PlgVers[$i]) ($($script:PlgMps[$i])) - $($script:PlgAuthors[$i])"
            }
        }
        if ((-not $quiet) -and $script:MarketplaceAvailable.Count -gt 0) {
            Write-Host "  $(_bold 'Available in marketplace:')"
            $sorted = $script:MarketplaceAvailable | Sort-Object -Unique
            Write-Host "    $($sorted -join ', ')"
        }
        if (-not $hasPlg) { Write-Host "  No plugins found." }
        Write-Host ""
    }

    # ── Connectors ──
    $webIdx = @(); $deskIdx = @(); $ncIdx = @()
    for ($i = 0; $i -lt $script:ConnCats.Count; $i++) {
        switch ($script:ConnCats[$i]) {
            'web'           { $webIdx  += $i }
            'desktop'       { $deskIdx += $i }
            'not_connected' { $ncIdx   += $i }
        }
    }
    if ((-not $quiet) -or ($webIdx.Count -gt 0) -or ($ncIdx.Count -gt 0)) {
        _section_hdr "CONNECTORS"
        if ($webIdx.Count -gt 0) {
            Write-Host "  $(_bold "Web") ($($webIdx.Count) connected)"
            $connRows = @()
            foreach ($idx in $webIdx) {
                $tag = if ($script:ConnTags[$idx]) { " ($($script:ConnTags[$idx]))" } else { "" }
                $tools = if ($script:ConnTools[$idx]) { "$($script:ConnTools[$idx])" } else { "-" }
                $connRows += ,@((Get-TruncatedString "$($script:ConnNames[$idx])$tag" 30), $tools)
            }
            Ascii-Table -headers @("Connector","Tools") -rows $connRows -widths @(30,6)
        }
        if ($deskIdx.Count -gt 0 -and -not $quiet) {
            Write-Host "  $(_bold "Desktop") ($($deskIdx.Count))"
            foreach ($idx in $deskIdx) {
                $tag = if ($script:ConnTags[$idx]) { "  $(_dim $script:ConnTags[$idx])" } else { "" }
                Write-Host "    $($script:ConnNames[$idx])$tag"
            }
        }
        if ($ncIdx.Count -gt 0) {
            Write-Host "  $(_bold "Not connected") ($($ncIdx.Count))"
            foreach ($idx in $ncIdx) { Write-Host "    $($script:ConnNames[$idx])" }
        }
        if ($webIdx.Count -eq 0 -and $ncIdx.Count -eq 0) { Write-Host "  No connectors found." }
        Write-Host ""
    }

    # ── Skills ──
    $uskIdx = @(); $pskIdx = @()
    for ($i = 0; $i -lt $script:SkSrcs.Count; $i++) {
        switch ($script:SkSrcs[$i]) {
            'user'   { $uskIdx += $i }
            'plugin' { $pskIdx += $i }
        }
    }
    if ((-not $quiet) -or ($uskIdx.Count -gt 0) -or ($pskIdx.Count -gt 0)) {
        _section_hdr "SKILLS"
        if ($uskIdx.Count -gt 0) {
            Write-Host "  $(_bold 'User-created:')"
            $skRows = @()
            foreach ($idx in $uskIdx) {
                $skRows += ,@(
                    (Get-TruncatedString $script:SkNames[$idx] 20),
                    (Get-TruncatedString $script:SkDescs[$idx] 30),
                    (Get-TruncatedString $script:SkPaths[$idx] 40)
                )
            }
            Ascii-Table -headers @("Name","Description","Path") -rows $skRows -widths @(20,30,40)
        }
        if ($pskIdx.Count -gt 0 -and -not $quiet) {
            Write-Host "  $(_bold 'Plugin skills:')"
            $pskRows = @()
            foreach ($idx in $pskIdx) {
                $plugName = if ($script:SkPlugins[$idx]) { $script:SkPlugins[$idx] } else { "unknown" }
                $pskRows += ,@(
                    (Get-TruncatedString $script:SkNames[$idx] 24),
                    (Get-TruncatedString $plugName 22),
                    (Get-TruncatedString $script:SkDescs[$idx] 40)
                )
            }
            Ascii-Table -headers @("Skill","Plugin","Description") -rows $pskRows -widths @(24,22,40)
        }
        elseif ($pskIdx.Count -gt 0) {
            $pns = @{}
            foreach ($idx in $pskIdx) {
                $pn = if ($script:SkPlugins[$idx]) { $script:SkPlugins[$idx] } else { "unknown" }
                $pns[$pn] = $true
            }
            Write-Host "  Plugin skills: $($pskIdx.Count) across $($pns.Keys -join ', ')"
        }
        if ($uskIdx.Count -eq 0 -and $pskIdx.Count -eq 0) { Write-Host "  No skills found." }
        Write-Host ""
    }

    # ── Scheduled Tasks ──
    $actIdx = @()
    for ($i = 0; $i -lt $script:StEnableds.Count; $i++) {
        if ($script:StEnableds[$i] -eq 'true') { $actIdx += $i }
    }
    if ((-not $quiet) -or ($actIdx.Count -gt 0)) {
        _section_hdr "SCHEDULED TASKS"
        $showIdx = @()
        if ($quiet) {
            $showIdx = $actIdx
        } else {
            for ($i = 0; $i -lt $script:StIds.Count; $i++) { $showIdx += $i }
        }
        if ($showIdx.Count -gt 0) {
            $stRows = @()
            foreach ($idx in $showIdx) {
                $desc = $script:StSNames[$idx]
                if (-not $desc) { $desc = $script:StSDescs[$idx] }
                if (-not $desc) { $desc = Get-TruncatedString $script:StPrompts[$idx] 28 }
                $en = if ($script:StEnableds[$idx] -eq 'true') { "Yes" } else { "No" }
                $stRows += ,@(
                    (Get-TruncatedString $script:StIds[$idx] 20),
                    (Get-TruncatedString $script:StCrons[$idx] 12),
                    (Get-TruncatedString $script:StCronEng[$idx] 22),
                    $en,
                    (Get-TruncatedString $desc 28)
                )
            }
            Ascii-Table -headers @("Task ID","Cron","Schedule","Enabled","Description") -rows $stRows -widths @(20,12,22,7,28)
            foreach ($idx in $showIdx) {
                if ($script:StFPaths[$idx]) {
                    Write-Host "    Skill: $(_dim $script:StFPaths[$idx])"
                }
            }
        } else {
            Write-Host "  No scheduled tasks found."
        }
        Write-Host ""
    }

    # ── Extensions ──
    if ((-not $quiet) -or ($script:ExtNames.Count -gt 0)) {
        _section_hdr "EXTENSIONS (DXT)"
        if ($script:ExtNames.Count -gt 0) {
            $showE = @()
            if ($quiet) {
                for ($i = 0; $i -lt $script:ExtSigneds.Count; $i++) {
                    if ($script:ExtSigneds[$i] -eq 'false' -or $script:ExtDangerStr[$i]) { $showE += $i }
                }
            } else {
                for ($i = 0; $i -lt $script:ExtNames.Count; $i++) { $showE += $i }
            }
            if ($showE.Count -gt 0) {
                $extRows = @()
                foreach ($idx in $showE) {
                    $stxt = if ($script:ExtSigneds[$idx] -eq 'true') { "Yes" } else { "No" }
                    $dng = if ($script:ExtDangerStr[$idx]) { $script:ExtDangerStr[$idx] -replace ',', ', ' } else { "-" }
                    $extRows += ,@(
                        (Get-TruncatedString $script:ExtNames[$idx] 20),
                        (Get-TruncatedString $script:ExtVers[$idx] 8),
                        (Get-TruncatedString $script:ExtAuthors[$idx] 12),
                        $stxt,
                        $dng
                    )
                }
                Ascii-Table -headers @("Name","Version","Author","Signed","Dangerous Tools") -rows $extRows -widths @(20,8,12,8,28)
            }
            # Extension settings - allowed directories
            if ($script:ExtSettingsJson -and $script:ExtSettingsJson.Count -gt 0) {
                foreach ($name in $script:ExtSettingsJson.Keys) {
                    try {
                        $esObj = $script:ExtSettingsJson[$name]
                        $allowed = $null
                        if ($esObj.userConfig.allowed_directories) {
                            $allowed = $esObj.userConfig.allowed_directories -join ", "
                        } elseif ($esObj.userConfig.allowedDirectories) {
                            $allowed = $esObj.userConfig.allowedDirectories -join ", "
                        }
                        if ($allowed) {
                            Write-Host "  Filesystem allowed directories: $allowed"
                        }
                    } catch { }
                }
            }
        } else {
            Write-Host "  No DXT extensions installed."
        }
        Write-Host ""
    }

    # ── Security Findings ──
    _section_hdr "SECURITY FINDINGS"
    $foundSec = $false
    for ($i = 0; $i -lt $script:FindingSev.Count; $i++) {
        if ($script:FindingSev[$i] -eq 'WARN') {
            Write-Host "  $(_sev_color 'WARN' '[WARN]') $($script:FindingMsg[$i])"
            $foundSec = $true
        }
    }
    if (-not $foundSec) { Write-Host "  $(_green 'No security issues detected.')" }
    Write-Host ""

    # ── Recommendations ──
    _section_hdr "RECOMMENDATIONS"
    if ($script:Recommendations.Count -gt 0) {
        for ($i = 0; $i -lt $script:Recommendations.Count; $i++) {
            Write-Host "  $($i + 1). $($script:Recommendations[$i])"
        }
    } else {
        Write-Host "  $(_green 'No issues requiring action.')"
    }
    Write-Host ""
    Write-Host (_dim "CLAUDIT v$($script:ScriptVersion) - read-only audit, no files modified.")
}

# ── HTML Renderer ────────────────────────────────────────────────────────────

function Render-Html {
    param([bool]$quiet = $false)

    $sb = [System.Text.StringBuilder]::new(32768)

    # Helper closures
    function _h([string]$s) { return (ConvertTo-HtmlEscaped $s) }

    function _badge_html([string]$sev) {
        $color = switch ($sev) {
            'CRITICAL' { '#dc3545' }
            'WARN'     { '#ffc107' }
            'INFO'     { '#17a2b8' }
            'OK'       { '#28a745' }
            'PASS'     { '#28a745' }
            'REVIEW'   { '#fd7e14' }
            default    { '#6c757d' }
        }
        return "<span class=`"badge`" style=`"background:$color;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em;`">$(_h $sev)</span>"
    }

    function _on_off_html([string]$val) {
        switch ($val) {
            'true'       { return '<span style="color:#ffc107;font-weight:600">ON</span>' }
            'false'      { return '<span style="color:#28a745">OFF</span>' }
            'configured' { return '<span style="color:#ffc107;font-weight:600">CONFIGURED</span>' }
            ''           { return '<span style="color:#666">-</span>' }
            default      { return (_h $val) }
        }
    }

    # Counts (pre-computed in Invoke-Audit)
    $nInst = $script:CountPluginInstalled; $nRem = $script:CountPluginRemote; $nCach = $script:CountPluginCached
    $nWeb = $script:CountConnWeb; $nNc = $script:CountConnNotConn
    $warnC = $script:WarnCount
    $revC = ($script:FindingSev | Where-Object { $_ -eq 'REVIEW' }).Count

    $dispBridgeStr = if ($script:DispatchBridgeEnabled -eq $true) { "CONFIGURED" } else { "off" }

    # HTML head + summary
    [void]$sb.AppendLine(@"
<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="generator" content="CLAUDIT v$($script:ScriptVersion)"><title>CLAUDIT Report &mdash; $(_h $script:HostnameVal) &mdash; $(_h $script:Timestamp)</title>
<style>
:root{--bg:#1a1a2e;--fg:#e0e0e0;--card:#16213e;--border:#0f3460;--accent:#e94560}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Mono',Menlo,Consolas,monospace;background:var(--bg);color:var(--fg);padding:20px;line-height:1.6}
.container{max-width:1100px;margin:0 auto} h1{color:var(--accent);font-size:1.8em;margin-bottom:5px}
h2{color:#e94560;font-size:1.2em;margin:20px 0 10px;border-bottom:1px solid var(--border);padding-bottom:5px}
h3{color:#aaa;font-size:1em;margin:12px 0 6px} .meta{color:#888;font-size:0.9em;margin-bottom:20px}
.risk-box{background:var(--card);border:2px solid var(--border);border-radius:8px;padding:15px 20px;margin:15px 0}
table{width:100%;border-collapse:collapse;margin:10px 0;background:var(--card);border-radius:6px;overflow:hidden}
th{background:var(--border);color:#fff;padding:8px 12px;text-align:left;font-size:0.9em}
td{padding:8px 12px;border-bottom:1px solid #0a1628;font-size:0.9em}
tr:nth-child(even){background:rgba(15,52,96,0.3)}
details{background:var(--card);border:1px solid var(--border);border-radius:6px;margin:10px 0}
summary{padding:10px 15px;cursor:pointer;font-weight:600;color:#e0e0e0}
summary:hover{color:var(--accent)} .detail-content{padding:10px 15px} .finding{padding:4px 0}
.setting-row{display:flex;gap:12px;padding:3px 0} .setting-key{color:#aaa;min-width:260px}
.setting-val{font-weight:600} .setting-warn{color:#ffc107;font-size:0.9em;margin-left:8px}
code{background:rgba(233,69,96,0.15);padding:2px 6px;border-radius:3px;font-size:0.9em}
.avail-list{color:#888;font-size:0.9em}
@media print{body{background:#fff;color:#000}th{background:#ddd;color:#000}tr:nth-child(even){background:#f5f5f5}}
</style></head><body><div class="container">
<h1>CLAUDIT &mdash; Claude Security Audit</h1>
<p class="meta">$(_h $script:Timestamp) &bull; Host: $(_h $script:HostnameVal) &bull; User: $(_h $script:AuditUser)</p>
<div class="risk-box">
<div>Scheduled tasks: <strong>$($script:StIds.Count)</strong> &bull; MCP servers: <strong>$($script:McpNames.Count)</strong> &bull; Extensions: <strong>$($script:ExtNames.Count)</strong></div>
<div>Plugins: <strong>$nInst</strong> installed, <strong>$nRem</strong> remote, <strong>$nCach</strong> cached &bull; Connectors: <strong>$nWeb</strong> web, <strong>$nNc</strong> not connected &bull; Skills: <strong>$($script:SkNames.Count)</strong></div>
<div style="margin-top:5px;">$(_badge_html "WARN") $warnC warnings &nbsp; $(_badge_html "REVIEW") $revC items to review</div>
$(if ($script:WsUuids.Count -gt 0) { "<div>Workspaces: <strong>$($script:WsUuids.Count)</strong> &bull; Dispatch bridge: <strong>$dispBridgeStr</strong></div>" })
</div>
"@)

    # ── Workspaces ──
    if ($script:WsUuids.Count -gt 1 -and -not $quiet) {
        [void]$sb.AppendLine('<details open><summary>Workspaces</summary><div class="detail-content">')
        [void]$sb.AppendLine('<table><tr><th>User UUID</th><th>Account</th><th>Email</th><th>Sessions</th><th>Indicators</th></tr>')
        for ($i = 0; $i -lt $script:WsUuids.Count; $i++) {
            $htmlInd = @()
            if ($script:WsDxtAllowlists[$i] -eq 'true')    { $htmlInd += "DXT-managed" }
            if ($script:WsHasRemotePlugins[$i] -eq 'true') { $htmlInd += "org-plugins" }
            if ($script:WsBridgeActive[$i] -eq 'true')     { $htmlInd += "dispatch-bridge" }
            $indStr = if ($htmlInd.Count -gt 0) { $htmlInd -join ", " } else { "-" }
            $acct  = if ($script:WsAcctNames[$i]) { _h $script:WsAcctNames[$i] } else { "-" }
            $email = if ($script:WsEmails[$i])    { _h $script:WsEmails[$i] }    else { "-" }
            $uidShort = (_h $script:WsUuids[$i].Substring(0, [Math]::Min(8, $script:WsUuids[$i].Length)))
            [void]$sb.AppendLine("<tr><td><code>${uidShort}...</code></td><td>$acct</td><td>$email</td><td>$($script:WsSessionCounts[$i])</td><td>$(_h $indStr)</td></tr>")
        }
        [void]$sb.AppendLine('</table></div></details>')
    }

    # ── Desktop Settings ──
    $kae = if ($script:DesktopPrefs['keepAwakeEnabled']) { $script:DesktopPrefs['keepAwakeEnabled'] } else { 'false' }
    if (-not $quiet) {
        [void]$sb.AppendLine('<details open><summary>Desktop Settings</summary><div class="detail-content">')
        $warnSpan = if ($kae -eq 'true') { '<span class="setting-warn">&#9888; Prevents Windows from sleeping</span>' } else { '' }
        [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">keepAwakeEnabled</span><span class=`"setting-val`">$(_on_off_html $kae)</span>$warnSpan</div>")
        $mbe = if ($script:DesktopPrefs['menuBarEnabled']) { $script:DesktopPrefs['menuBarEnabled'] } else { 'false' }
        [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">menuBarEnabled</span><span class=`"setting-val`">$(_on_off_html $mbe)</span></div>")
        $sm = if ($script:DesktopPrefs['sidebarMode']) { _h $script:DesktopPrefs['sidebarMode'] } else { "-" }
        [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">sidebarMode</span><span class=`"setting-val`">$sm</span></div>")
        $qes = if ($script:DesktopPrefs['quickEntryShortcut']) { _h $script:DesktopPrefs['quickEntryShortcut'] } else { "-" }
        [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">quickEntryShortcut</span><span class=`"setting-val`">$qes</span></div>")
        [void]$sb.AppendLine('</div></details>')
    }
    elseif ($kae -eq 'true') {
        [void]$sb.AppendLine("<details open><summary>Desktop Settings</summary><div class=`"detail-content`"><div class=`"setting-row`"><span class=`"setting-key`">keepAwakeEnabled</span><span class=`"setting-val`">$(_on_off_html 'true')</span><span class=`"setting-warn`">&#9888; Prevents Windows from sleeping</span></div></div></details>")
    }

    # ── Cowork Settings ──
    $cst = if ($script:CoworkPrefs['coworkScheduledTasksEnabled']) { $script:CoworkPrefs['coworkScheduledTasksEnabled'] } else { 'false' }
    $ccd = if ($script:CoworkPrefs['ccdScheduledTasksEnabled'])    { $script:CoworkPrefs['ccdScheduledTasksEnabled'] }    else { 'false' }
    $cws = if ($script:CoworkPrefs['coworkWebSearchEnabled'])      { $script:CoworkPrefs['coworkWebSearchEnabled'] }      else { 'false' }
    $aba = if ($script:CoworkPrefs['allowAllBrowserActions'])      { $script:CoworkPrefs['allowAllBrowserActions'] }      else { 'false' }

    $coworkTuples = @(
        @{ key='coworkScheduledTasksEnabled'; label='scheduledTasksEnabled'; wmsg='Autonomous task execution' },
        @{ key='ccdScheduledTasksEnabled';    label='ccdScheduledTasksEnabled'; wmsg='Code Desktop scheduled tasks' },
        @{ key='coworkWebSearchEnabled';      label='webSearchEnabled'; wmsg='Autonomous internet access' },
        @{ key='allowAllBrowserActions';      label='allowAllBrowserActions'; wmsg='Browse any website without asking' }
    )

    if (-not $quiet) {
        [void]$sb.AppendLine('<details open><summary>Cowork Settings</summary><div class="detail-content">')
        foreach ($tuple in $coworkTuples) {
            $val = if ($script:CoworkPrefs[$tuple.key]) { $script:CoworkPrefs[$tuple.key] } else { 'false' }
            $warnSpan = if ($val -eq 'true') { "<span class=`"setting-warn`">&#9888; $(_h $tuple.wmsg)</span>" } else { '' }
            [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">$(_h $tuple.label)</span><span class=`"setting-val`">$(_on_off_html $val)</span>$warnSpan</div>")
        }
        # Dispatch
        $htmlDispState = 'false'
        if ($script:DispatchBridgeEnabled -eq $true) { $htmlDispState = 'configured' }
        if ($script:DispatchActive -eq $true)        { $htmlDispState = 'true' }
        $dispWarn = ''
        if ($script:DispatchActive -eq $true) {
            $dispWarn = '<span class="setting-warn">&#9888; Actively accepting dispatched tasks</span>'
        } elseif ($script:DispatchBridgeEnabled -eq $true) {
            $dispWarn = '<span class="setting-warn">&#9888; Bridge configured - phone can dispatch tasks</span>'
        }
        [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">dispatch (mobile&#8594;desktop)</span><span class=`"setting-val`">$(_on_off_html $htmlDispState)</span>$dispWarn</div>")

        $nm = if ($script:CoworkNetworkMode) { _h $script:CoworkNetworkMode } else { "-" }
        [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">networkMode</span><span class=`"setting-val`">$nm</span></div>")

        if ($script:EgressUnrestricted -eq $true) {
            [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">egressAllowedDomains</span><span class=`"setting-val`">$(_on_off_html 'true')</span><span class=`"setting-warn`">&#9888; All domains reachable</span></div>")
        } elseif ($script:EgressDomains) {
            [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">egressAllowedDomains</span><span class=`"setting-val`">$(_h 'restricted')</span></div>")
        }
        if ($script:DisabledMcpTools.Count -gt 0) {
            [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">Disabled MCP tools</span><span class=`"setting-val`">$($script:DisabledMcpTools.Count) tool(s)</span></div>")
        }
        if ($script:CoworkEnabledPlugins.Count -gt 0) {
            [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">Enabled plugins</span><span class=`"setting-val`">$(_h ($script:CoworkEnabledPlugins -join ', '))</span></div>")
        }
        [void]$sb.AppendLine('</div></details>')
    }
    else {
        # Quiet mode: only show items with warnings
        $hasCoworkWarn = ($cst -eq 'true' -or $ccd -eq 'true' -or $cws -eq 'true' -or $aba -eq 'true' -or
                          $script:DispatchActive -eq $true -or $script:DispatchBridgeEnabled -eq $true -or
                          $script:EgressUnrestricted -eq $true)
        if ($hasCoworkWarn) {
            [void]$sb.AppendLine('<details open><summary>Cowork Settings</summary><div class="detail-content">')
            foreach ($tuple in $coworkTuples) {
                $val = if ($script:CoworkPrefs[$tuple.key]) { $script:CoworkPrefs[$tuple.key] } else { 'false' }
                if ($val -eq 'true') {
                    [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">$(_h $tuple.label)</span><span class=`"setting-val`">$(_on_off_html 'true')</span><span class=`"setting-warn`">&#9888; $(_h $tuple.wmsg)</span></div>")
                }
            }
            if ($script:DispatchActive -eq $true) {
                [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">dispatch (mobile&#8594;desktop)</span><span class=`"setting-val`">$(_on_off_html 'true')</span><span class=`"setting-warn`">&#9888; Actively accepting dispatched tasks</span></div>")
            }
            if ($script:DispatchBridgeEnabled -eq $true -and $script:DispatchActive -ne $true) {
                [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">dispatch (mobile&#8594;desktop)</span><span class=`"setting-val`">$(_on_off_html 'configured')</span><span class=`"setting-warn`">&#9888; Bridge configured - phone can dispatch tasks</span></div>")
            }
            if ($script:EgressUnrestricted -eq $true) {
                [void]$sb.AppendLine("<div class=`"setting-row`"><span class=`"setting-key`">egressAllowedDomains</span><span class=`"setting-val`">$(_on_off_html 'true')</span><span class=`"setting-warn`">&#9888; All domains reachable</span></div>")
            }
            [void]$sb.AppendLine('</div></details>')
        }
    }

    # ── Plugin Hooks ──
    if ($script:HookPlugins.Count -gt 0) {
        [void]$sb.AppendLine('<details open><summary>Plugin Hooks</summary><div class="detail-content">')
        [void]$sb.AppendLine('<table><tr><th>Plugin</th><th>Event</th><th>Command</th></tr>')
        for ($i = 0; $i -lt $script:HookPlugins.Count; $i++) {
            [void]$sb.AppendLine("<tr><td>$(_h $script:HookPlugins[$i])</td><td>$(_h $script:HookEvents[$i])</td><td><code>$(_h $script:HookCmds[$i])</code></td></tr>")
        }
        [void]$sb.AppendLine('</table></div></details>')
    }

    # ── MCP Servers ──
    if ((-not $quiet) -or ($script:McpNames.Count -gt 0)) {
        [void]$sb.AppendLine('<details open><summary>MCP Servers</summary><div class="detail-content">')
        if ($script:McpNames.Count -gt 0) {
            [void]$sb.AppendLine('<table><tr><th>Name</th><th>Command</th><th>Args</th><th>Env Vars</th></tr>')
            for ($i = 0; $i -lt $script:McpNames.Count; $i++) {
                [void]$sb.AppendLine("<tr><td>$(_h $script:McpNames[$i])</td><td><code>$(_h $script:McpCmds[$i])</code></td><td>$(_h $script:McpArgsStr[$i])</td><td>$(_h $script:McpEnvKeys[$i])</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
            [void]$sb.AppendLine("<div class=`"finding`">$(_badge_html 'REVIEW') MCP servers execute with Claude's permissions.</div>")
        } else {
            [void]$sb.AppendLine('<p>No MCP servers configured.</p>')
        }
        [void]$sb.AppendLine('</div></details>')
    }

    # ── Plugins ──
    $hasPlg = ($nInst -gt 0 -or $nRem -gt 0 -or $nCach -gt 0)
    if ((-not $quiet) -or $hasPlg) {
        [void]$sb.AppendLine('<details open><summary>Plugins</summary><div class="detail-content">')
        if ($nInst -gt 0) {
            [void]$sb.AppendLine('<h3>Installed</h3><table><tr><th>Name</th><th>Version</th><th>Source</th><th>Scope</th><th>Installed</th></tr>')
            for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
                if ($script:PlgSrcs[$i] -ne 'installed') { continue }
                $instDate = if ($script:PlgInstalledAts[$i] -and $script:PlgInstalledAts[$i].Length -ge 10) { _h $script:PlgInstalledAts[$i].Substring(0,10) } else { '-' }
                [void]$sb.AppendLine("<tr><td>$(_h $script:PlgNames[$i])</td><td>$(_h $script:PlgVers[$i])</td><td>$(_h $script:PlgMps[$i])</td><td>$(_h $script:PlgScopes[$i])</td><td>$instDate</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        if ($nRem -gt 0) {
            [void]$sb.AppendLine('<h3>Remote (org-deployed)</h3><table><tr><th>Name</th><th>Version</th><th>Author</th><th>Marketplace</th><th>Skills</th></tr>')
            for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
                if ($script:PlgSrcs[$i] -ne 'remote') { continue }
                [void]$sb.AppendLine("<tr><td>$(_h $script:PlgNames[$i])</td><td>$(_h $script:PlgVers[$i])</td><td>$(_h $script:PlgAuthors[$i])</td><td>$(_h $script:PlgMps[$i])</td><td>$($script:PlgSkillCounts[$i])</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        if ($nCach -gt 0) {
            [void]$sb.AppendLine('<h3>Cached</h3><table><tr><th>Name</th><th>Version</th><th>Author</th><th>Marketplace</th></tr>')
            for ($i = 0; $i -lt $script:PlgSrcs.Count; $i++) {
                if ($script:PlgSrcs[$i] -ne 'cached') { continue }
                [void]$sb.AppendLine("<tr><td>$(_h $script:PlgNames[$i])</td><td>$(_h $script:PlgVers[$i])</td><td>$(_h $script:PlgAuthors[$i])</td><td>$(_h $script:PlgMps[$i])</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        if ((-not $quiet) -and $script:MarketplaceAvailable.Count -gt 0) {
            $avail = ($script:MarketplaceAvailable | Sort-Object -Unique) -join ', '
            [void]$sb.AppendLine("<h3>Available in marketplace</h3><p class=`"avail-list`">$(_h $avail)</p>")
        }
        if (-not $hasPlg) { [void]$sb.AppendLine('<p>No plugins found.</p>') }
        [void]$sb.AppendLine('</div></details>')
    }

    # ── Connectors ──
    if ((-not $quiet) -or ($nWeb -gt 0) -or ($nNc -gt 0)) {
        [void]$sb.AppendLine('<details open><summary>Connectors</summary><div class="detail-content">')
        if ($nWeb -gt 0) {
            [void]$sb.AppendLine("<h3>Web ($nWeb connected)</h3><table><tr><th>Connector</th><th>Tools</th></tr>")
            for ($i = 0; $i -lt $script:ConnCats.Count; $i++) {
                if ($script:ConnCats[$i] -ne 'web') { continue }
                $tools = if ($script:ConnTools[$i]) { "$($script:ConnTools[$i])" } else { "-" }
                [void]$sb.AppendLine("<tr><td>$(_h $script:ConnNames[$i])</td><td>$tools</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        $nDesk = $script:CountConnDesktop
        if ($nDesk -gt 0 -and -not $quiet) {
            [void]$sb.AppendLine("<h3>Desktop ($nDesk)</h3><table><tr><th>Connector</th><th>Tags</th></tr>")
            for ($i = 0; $i -lt $script:ConnCats.Count; $i++) {
                if ($script:ConnCats[$i] -ne 'desktop') { continue }
                $tag = if ($script:ConnTags[$i]) { _h $script:ConnTags[$i] } else { "-" }
                [void]$sb.AppendLine("<tr><td>$(_h $script:ConnNames[$i])</td><td>$tag</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        if ($nNc -gt 0) {
            [void]$sb.AppendLine("<h3>Not connected ($nNc)</h3><table><tr><th>Connector</th></tr>")
            for ($i = 0; $i -lt $script:ConnCats.Count; $i++) {
                if ($script:ConnCats[$i] -ne 'not_connected') { continue }
                [void]$sb.AppendLine("<tr><td>$(_h $script:ConnNames[$i])</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        if ($nWeb -eq 0 -and $nNc -eq 0) { [void]$sb.AppendLine('<p>No connectors found.</p>') }
        [void]$sb.AppendLine('</div></details>')
    }

    # ── Skills ──
    $nUsk = 0; $nPsk = 0
    for ($i = 0; $i -lt $script:SkSrcs.Count; $i++) {
        if ($script:SkSrcs[$i] -eq 'user') { $nUsk++ } else { $nPsk++ }
    }
    if ((-not $quiet) -or ($nUsk -gt 0) -or ($nPsk -gt 0)) {
        [void]$sb.AppendLine('<details open><summary>Skills</summary><div class="detail-content">')
        if ($nUsk -gt 0) {
            [void]$sb.AppendLine('<h3>User-created</h3><table><tr><th>Name</th><th>Description</th><th>Path</th></tr>')
            for ($i = 0; $i -lt $script:SkSrcs.Count; $i++) {
                if ($script:SkSrcs[$i] -ne 'user') { continue }
                $descTrunc = if ($script:SkDescs[$i].Length -gt 80) { (_h $script:SkDescs[$i].Substring(0,80)) } else { (_h $script:SkDescs[$i]) }
                [void]$sb.AppendLine("<tr><td>$(_h $script:SkNames[$i])</td><td>$descTrunc</td><td><code>$(_h $script:SkPaths[$i])</code></td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        if ($nPsk -gt 0 -and -not $quiet) {
            [void]$sb.AppendLine('<h3>Plugin skills</h3><table><tr><th>Skill</th><th>Plugin</th><th>Description</th></tr>')
            for ($i = 0; $i -lt $script:SkSrcs.Count; $i++) {
                if ($script:SkSrcs[$i] -ne 'plugin') { continue }
                $plugName = if ($script:SkPlugins[$i]) { _h $script:SkPlugins[$i] } else { "unknown" }
                $descTrunc = if ($script:SkDescs[$i].Length -gt 80) { (_h $script:SkDescs[$i].Substring(0,80)) } else { (_h $script:SkDescs[$i]) }
                [void]$sb.AppendLine("<tr><td>$(_h $script:SkNames[$i])</td><td>$plugName</td><td>$descTrunc</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        elseif ($nPsk -gt 0) {
            $pns = @{}
            for ($i = 0; $i -lt $script:SkSrcs.Count; $i++) {
                if ($script:SkSrcs[$i] -eq 'plugin') {
                    $pn = if ($script:SkPlugins[$i]) { $script:SkPlugins[$i] } else { "unknown" }
                    $pns[$pn] = $true
                }
            }
            [void]$sb.AppendLine("<p>Plugin skills: $nPsk across $(_h ($pns.Keys -join ', '))</p>")
        }
        if ($nUsk -eq 0 -and $nPsk -eq 0) { [void]$sb.AppendLine('<p>No skills found.</p>') }
        [void]$sb.AppendLine('</div></details>')
    }

    # ── Scheduled Tasks ──
    $nAct = 0
    for ($i = 0; $i -lt $script:StEnableds.Count; $i++) {
        if ($script:StEnableds[$i] -eq 'true') { $nAct++ }
    }
    if ((-not $quiet) -or ($nAct -gt 0)) {
        [void]$sb.AppendLine('<details open><summary>Scheduled Tasks</summary><div class="detail-content">')
        if ($script:StIds.Count -gt 0) {
            [void]$sb.AppendLine('<table><tr><th>Task ID</th><th>Cron</th><th>Schedule</th><th>Enabled</th><th>Description</th><th>Skill Path</th></tr>')
            for ($i = 0; $i -lt $script:StIds.Count; $i++) {
                if ($quiet -and $script:StEnableds[$i] -ne 'true') { continue }
                $desc = $script:StSNames[$i]
                if (-not $desc) { $desc = $script:StSDescs[$i] }
                if (-not $desc -and $script:StPrompts[$i]) { $desc = $script:StPrompts[$i].Substring(0, [Math]::Min(60, $script:StPrompts[$i].Length)) }
                $en = if ($script:StEnableds[$i] -eq 'true') { '<span style="color:#28a745">Yes</span>' } else { 'No' }
                [void]$sb.AppendLine("<tr><td>$(_h $script:StIds[$i])</td><td><code>$(_h $script:StCrons[$i])</code></td><td>$(_h $script:StCronEng[$i])</td><td>$en</td><td>$(_h $desc)</td><td><code>$(_h $script:StFPaths[$i])</code></td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        } else {
            [void]$sb.AppendLine('<p>No scheduled tasks found.</p>')
        }
        [void]$sb.AppendLine('</div></details>')
    }

    # ── Extensions ──
    if ((-not $quiet) -or ($script:ExtNames.Count -gt 0)) {
        [void]$sb.AppendLine('<details open><summary>Extensions (DXT)</summary><div class="detail-content">')
        if ($script:ExtNames.Count -gt 0) {
            [void]$sb.AppendLine('<table><tr><th>Name</th><th>Version</th><th>Author</th><th>Signed</th><th>Dangerous Tools</th></tr>')
            for ($i = 0; $i -lt $script:ExtNames.Count; $i++) {
                if ($quiet -and $script:ExtSigneds[$i] -eq 'true' -and -not $script:ExtDangerStr[$i]) { continue }
                $sh = if ($script:ExtSigneds[$i] -eq 'true') { '<span style="color:#28a745">Yes</span>' } else { '<span style="color:#ffc107">No</span>' }
                $dh = "-"
                if ($script:ExtDangerStr[$i]) {
                    $dh = ""
                    foreach ($t in ($script:ExtDangerStr[$i] -split ',')) {
                        $dh += "<code>$(_h $t.Trim())</code> "
                    }
                }
                [void]$sb.AppendLine("<tr><td>$(_h $script:ExtNames[$i])</td><td>$(_h $script:ExtVers[$i])</td><td>$(_h $script:ExtAuthors[$i])</td><td>$sh</td><td>$dh</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        } else {
            [void]$sb.AppendLine('<p>No DXT extensions installed.</p>')
        }
        [void]$sb.AppendLine('</div></details>')
    }

    # ── Security Findings ──
    [void]$sb.AppendLine('<details open><summary>Security Findings</summary><div class="detail-content">')
    $fany = $false
    for ($i = 0; $i -lt $script:FindingSev.Count; $i++) {
        if ($script:FindingSev[$i] -ne 'WARN') { continue }
        [void]$sb.AppendLine("<div class=`"finding`">$(_badge_html 'WARN') $(_h $script:FindingMsg[$i])</div>")
        $fany = $true
    }
    if (-not $fany) { [void]$sb.AppendLine('<p style="color:#28a745">No security issues detected.</p>') }
    [void]$sb.AppendLine('</div></details>')

    # ── Recommendations ──
    [void]$sb.AppendLine('<details open><summary>Recommendations</summary><div class="detail-content">')
    if ($script:Recommendations.Count -gt 0) {
        [void]$sb.AppendLine('<ol>')
        for ($i = 0; $i -lt $script:Recommendations.Count; $i++) {
            [void]$sb.AppendLine("<li style=`"margin-bottom:8px;`">$(_h $script:Recommendations[$i])</li>")
        }
        [void]$sb.AppendLine('</ol>')
    } else {
        [void]$sb.AppendLine('<p style="color:#28a745">No issues requiring action.</p>')
    }
    [void]$sb.AppendLine('</div></details>')

    # ── Runtime Info (non-quiet only) ──
    if (-not $quiet) {
        [void]$sb.AppendLine('<details><summary>Runtime Info</summary><div class="detail-content">')
        for ($i = 0; $i -lt $script:FindingSev.Count; $i++) {
            if ($script:FindingSect[$i] -eq 'Runtime') {
                [void]$sb.AppendLine("<div class=`"finding`">$(_badge_html $script:FindingSev[$i]) $(_h $script:FindingMsg[$i])</div>")
            }
        }
        if ($script:RuntimeInfo -and $script:RuntimeInfo['ant_did']) {
            [void]$sb.AppendLine("<div>Device ID: <code>$(_h $script:RuntimeInfo['ant_did'])</code></div>")
        }
        [void]$sb.AppendLine('</div></details>')
    }

    # Footer
    [void]$sb.AppendLine("<p class=`"meta`" style=`"margin-top:30px;`">CLAUDIT v$($script:ScriptVersion) &mdash; read-only audit, no files modified.</p>")
    [void]$sb.AppendLine('</div></body></html>')

    return $sb.ToString()
}

# ── JSON Renderer ────────────────────────────────────────────────────────────

function Redact-Sensitive {
    <#
    .SYNOPSIS
        Walks an object tree and redacts values matching sensitive patterns.
        Operates on PSCustomObjects, hashtables, arrays, and strings.
    #>
    param([object]$obj)

    $sensitiveKeyPattern = '(?i)(oauth|token|tokenCache|secret|password|credential|apiKey|api_key|access_token|refresh_token|private_key|privateKey)'
    $sensitiveValuePattern = $script:REDACT_PATTERN

    if ($null -eq $obj) { return $null }

    if ($obj -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($obj.Keys)) {
            if ($key -match $sensitiveKeyPattern) {
                $result[$key] = '[REDACTED]'
            } else {
                $result[$key] = Redact-Sensitive $obj[$key]
            }
        }
        return $result
    }
    elseif ($obj -is [PSCustomObject]) {
        $result = [ordered]@{}
        foreach ($prop in $obj.PSObject.Properties) {
            if ($prop.Name -match $sensitiveKeyPattern) {
                $result[$prop.Name] = '[REDACTED]'
            } else {
                $result[$prop.Name] = Redact-Sensitive $prop.Value
            }
        }
        return [PSCustomObject]$result
    }
    elseif ($obj -is [System.Collections.IList]) {
        $result = @()
        foreach ($item in $obj) {
            $result += (Redact-Sensitive $item)
        }
        return $result
    }
    elseif ($obj -is [string]) {
        if ($obj -match $sensitiveValuePattern) {
            return '[REDACTED]'
        }
        return $obj
    }
    else {
        return $obj
    }
}

function Render-Json {
    # Build the full JSON object using ordered hashtables, then redact and serialize

    # Findings array
    $findings = @()
    for ($i = 0; $i -lt $script:FindingSev.Count; $i++) {
        $findings += [ordered]@{
            severity = $script:FindingSev[$i]
            section  = $script:FindingSect[$i]
            message  = $script:FindingMsg[$i]
            detail   = $script:FindingDet[$i]
        }
    }

    # Desktop prefs
    $desktopPrefs = [ordered]@{
        keepAwakeEnabled = if ($script:DesktopPrefs['keepAwakeEnabled'] -eq 'true') { $true } else { $false }
        menuBarEnabled   = if ($script:DesktopPrefs['menuBarEnabled'] -eq 'true')   { $true } else { $false }
    }

    # Cowork prefs
    $coworkPrefs = [ordered]@{
        coworkScheduledTasksEnabled = if ($script:CoworkPrefs['coworkScheduledTasksEnabled'] -eq 'true') { $true } else { $false }
        ccdScheduledTasksEnabled    = if ($script:CoworkPrefs['ccdScheduledTasksEnabled'] -eq 'true')    { $true } else { $false }
        coworkWebSearchEnabled      = if ($script:CoworkPrefs['coworkWebSearchEnabled'] -eq 'true')      { $true } else { $false }
        allowAllBrowserActions      = if ($script:CoworkPrefs['allowAllBrowserActions'] -eq 'true')      { $true } else { $false }
        dispatchActive              = if ($script:DispatchActive -eq $true)          { $true } else { $false }
        dispatchSessionCount        = [int]$script:DispatchSessionCount
        dispatchBridgeEnabled       = if ($script:DispatchBridgeEnabled -eq $true)   { $true } else { $false }
        dispatchBridgeConsented     = if ($script:DispatchBridgeConsented -eq $true)  { $true } else { $false }
    }

    # MCP servers
    $mcpServers = @()
    for ($i = 0; $i -lt $script:McpNames.Count; $i++) {
        $mcpServers += [ordered]@{
            name     = $script:McpNames[$i]
            command  = $script:McpCmds[$i]
            args     = $script:McpArgsStr[$i]
            env_keys = $script:McpEnvKeys[$i]
        }
    }

    # Plugins
    $plugins = @()
    for ($i = 0; $i -lt $script:PlgNames.Count; $i++) {
        $plugins += [ordered]@{
            name        = $script:PlgNames[$i]
            version     = $script:PlgVers[$i]
            source      = $script:PlgSrcs[$i]
            author      = $script:PlgAuthors[$i]
            marketplace = $script:PlgMps[$i]
            skill_count = [int]$(if ($script:PlgSkillCounts[$i]) { $script:PlgSkillCounts[$i] } else { 0 })
        }
    }

    # Connectors
    $connectors = @()
    for ($i = 0; $i -lt $script:ConnNames.Count; $i++) {
        $connectors += [ordered]@{
            name       = $script:ConnNames[$i]
            category   = $script:ConnCats[$i]
            tool_count = [int]$(if ($script:ConnTools[$i]) { $script:ConnTools[$i] } else { 0 })
        }
    }

    # Skills
    $skills = @()
    for ($i = 0; $i -lt $script:SkNames.Count; $i++) {
        $skills += [ordered]@{
            name        = $script:SkNames[$i]
            description = $script:SkDescs[$i]
            source      = $script:SkSrcs[$i]
            plugin_name = $script:SkPlugins[$i]
        }
    }

    # Scheduled tasks
    $scheduledTasks = @()
    for ($i = 0; $i -lt $script:StIds.Count; $i++) {
        $scheduledTasks += [ordered]@{
            task_id         = $script:StIds[$i]
            cron_expression = $script:StCrons[$i]
            cron_english    = $script:StCronEng[$i]
            enabled         = if ($script:StEnableds[$i] -eq 'true') { $true } else { $false }
            file_path       = $script:StFPaths[$i]
            skill_name      = $script:StSNames[$i]
        }
    }

    # Extensions
    $extensions = @()
    for ($i = 0; $i -lt $script:ExtNames.Count; $i++) {
        $extensions += [ordered]@{
            ext_id           = $script:ExtIds[$i]
            name             = $script:ExtNames[$i]
            version          = $script:ExtVers[$i]
            author           = $script:ExtAuthors[$i]
            signed           = if ($script:ExtSigneds[$i] -eq 'true') { $true } else { $false }
            signature_status = $script:ExtSigStats[$i]
            dangerous_tools  = $script:ExtDangerStr[$i]
        }
    }

    # Workspaces
    $workspaces = @()
    for ($i = 0; $i -lt $script:WsUuids.Count; $i++) {
        $wsDxt = if ($script:WsDxtAllowlists[$i] -eq 'true') { $true } else { $false }
        $workspaces += [ordered]@{
            userUuid           = $script:WsUuids[$i]
            accountName        = $script:WsAcctNames[$i]
            email              = $script:WsEmails[$i]
            sessionCount       = [int]$(if ($script:WsSessionCounts[$i]) { $script:WsSessionCounts[$i] } else { 0 })
            dxtAllowlistEnabled = $wsDxt
            hasRemotePlugins   = if ($script:WsHasRemotePlugins[$i] -eq 'true') { $true } else { $false }
            bridgeActive       = if ($script:WsBridgeActive[$i] -eq 'true') { $true } else { $false }
        }
    }

    # Egress domains
    $egressDomains = $null
    if ($script:EgressUnrestricted -eq $true) {
        $egressDomains = @('*')
    } elseif ($script:EgressDomains) {
        $egressDomains = @($script:EgressDomains -split '[,\s]+' | Where-Object { $_ })
    }

    # Disabled MCP tools
    $disabledTools = @($script:DisabledMcpTools)

    # Plugin hooks
    $pluginHooks = @()
    for ($i = 0; $i -lt $script:HookPlugins.Count; $i++) {
        $pluginHooks += [ordered]@{
            plugin  = $script:HookPlugins[$i]
            event   = $script:HookEvents[$i]
            command = $script:HookCmds[$i]
        }
    }

    # Claude Code settings - already a PSCustomObject from Read-SafeJson
    $claudeCodeObj = if ($script:ClaudeCodeJson) { $script:ClaudeCodeJson } else { [PSCustomObject]@{} }

    # Managed policy (admin-deployed managed-mcp.json / managed-settings.json)
    $managedMcp = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $script:ManagedMcpNames.Count; $i++) {
        [void]$managedMcp.Add([ordered]@{
            name     = $script:ManagedMcpNames[$i]
            command  = $script:ManagedMcpCmds[$i]
            args     = $script:ManagedMcpArgsStr[$i]
            env_keys = $script:ManagedMcpEnvKeys[$i]
            source   = $script:ManagedMcpSources[$i]
        })
    }
    $mpFiles  = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $script:ManagedPolicyFiles)  { [void]$mpFiles.Add($p) }
    $mpLegacy = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $script:ManagedPolicyLegacy) { [void]$mpLegacy.Add($p) }
    $mpKeys   = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $script:ManagedSettingsKeys) { [void]$mpKeys.Add($k) }
    $managedPolicy = [ordered]@{
        files_found        = $mpFiles
        legacy_paths_found = $mpLegacy
        legacy_path_in_use = [bool]$script:ManagedSettingsLegacyHit
        managed_mcp        = $managedMcp
        settings_keys      = $mpKeys
    }

    # Home directory
    $homeDir = if ($script:AuditUser) {
        "C:\Users\$($script:AuditUser)"
    } else {
        $env:USERPROFILE
    }

    # Build the top-level object
    $jsonObj = [ordered]@{
        timestamp             = [string]$script:Timestamp
        hostname              = [string]$script:HostnameVal
        username              = [string]$script:AuditUser
        home_dir              = [string]$homeDir
        findings              = $findings
        desktop_prefs         = $desktopPrefs
        cowork_prefs          = $coworkPrefs
        cowork_network_mode   = $(if ($script:CoworkNetworkMode) { $script:CoworkNetworkMode } else { '' })
        egress_allowed_domains = $egressDomains
        disabled_mcp_tools    = $disabledTools
        plugin_hooks          = $pluginHooks
        mcp_servers           = $mcpServers
        plugins               = $plugins
        connectors            = $connectors
        skills                = $skills
        scheduled_tasks       = $scheduledTasks
        extensions            = $extensions
        blocklist_entries     = [int]$script:BlocklistEntries
        blocklist_status      = $(if ($script:BlocklistStatus) { $script:BlocklistStatus } else { '' })
        claude_code_settings  = $claudeCodeObj
        managed_policy        = $managedPolicy
        workspaces            = $workspaces
        org_uuid              = $(if ($script:WsOrgUuid) { $script:WsOrgUuid } else { '' })
        warn_count            = [int]$script:WarnCount
        info_count            = [int]$script:InfoCount
    }

    # Redact sensitive fields
    $redacted = Redact-Sensitive $jsonObj

    # Fix PS 5.1 empty array serialization (empty @() becomes {} instead of [])
    $arrayKeys = @('findings','egress_allowed_domains','disabled_mcp_tools','plugin_hooks',
                   'mcp_servers','plugins','connectors','skills','scheduled_tasks',
                   'extensions','workspaces')
    foreach ($aKey in $arrayKeys) {
        if ($null -eq $redacted[$aKey] -or ($redacted[$aKey] -is [array] -and $redacted[$aKey].Count -eq 0)) {
            $redacted[$aKey] = [System.Collections.Generic.List[object]]::new()
        }
    }

    # Same fix for nested arrays inside managed_policy
    if ($redacted['managed_policy']) {
        foreach ($mpKey in @('files_found','legacy_paths_found','managed_mcp','settings_keys')) {
            $mpVal = $redacted['managed_policy'][$mpKey]
            if ($null -eq $mpVal -or ($mpVal -is [array] -and $mpVal.Count -eq 0)) {
                $redacted['managed_policy'][$mpKey] = [System.Collections.Generic.List[object]]::new()
            }
        }
    }

    # Serialize to JSON
    return ($redacted | ConvertTo-Json -Depth 10 -Compress)
}

# ── HTML File Writer ─────────────────────────────────────────────────────────

function Write-HtmlReport {
    <#
    .SYNOPSIS
        Writes the HTML report to a file with restricted permissions.
        Only the current user gets access (equivalent to umask 077 / mode 0600).
    #>
    param(
        [string]$FilePath,
        [string]$HtmlContent
    )

    # Write the file
    [System.IO.File]::WriteAllText($FilePath, $HtmlContent, [System.Text.Encoding]::UTF8)

    # Restrict permissions: remove inherited ACLs, grant only current user FullControl
    try {
        $acl = Get-Acl -Path $FilePath
        $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, remove inherited rules
        # Remove all existing rules
        foreach ($rule in @($acl.Access)) {
            [void]$acl.RemoveAccessRule($rule)
        }
        # Add rule for current user only
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $FilePath -AclObject $acl
    } catch {
        Write-Warning "Could not restrict permissions on $FilePath : $_"
    }
}

# ── Run Audit ────────────────────────────────────────────────────────────────

function Invoke-Audit {
    <#
    .SYNOPSIS
        Runs the full audit for a single user. Resets state, discovers sessions,
        runs all collectors, counts findings, and builds recommendations.
    #>
    param(
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$HomeDir
    )

    Reset-AuditState

    $script:AuditUser   = $Username
    $script:HomeDir     = $HomeDir
    $script:HostnameVal = $env:COMPUTERNAME
    if (-not $script:HostnameVal) { $script:HostnameVal = "unknown" }
    $script:Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"

    $claudeDir = Join-Path (Join-Path $HomeDir "AppData\Roaming") $script:CLAUDE_DESKTOP_DIR

    if (-not (Test-Path -LiteralPath $claudeDir -PathType Container)) {
        Add-Finding -Severity "INFO" -Section "General" -Message "Claude Desktop directory not found: $claudeDir"
    }

    Find-SessionDirs -ClaudeDir $claudeDir

    # ── Run Data Collectors ──
    Collect-DesktopSettings -ClaudeDir $claudeDir
    Collect-CoworkSettings
    Collect-AppConfig -ClaudeDir $claudeDir
    Collect-Extensions -ClaudeDir $claudeDir
    Collect-ExtensionSettings -ClaudeDir $claudeDir
    Collect-Plugins
    Collect-PluginHooks -HomeDir $HomeDir
    Collect-Connectors -ClaudeDir $claudeDir
    Collect-Workspaces -ClaudeDir $claudeDir
    Collect-Skills -HomeDir $HomeDir
    Collect-ScheduledTasks
    Collect-Blocklist -ClaudeDir $claudeDir
    Collect-ClaudeCodeSettings -HomeDir $HomeDir
    Collect-ClaudeCodeManagedPolicy
    Collect-Runtime -ClaudeDir $claudeDir -HomeDir $HomeDir

    # Count findings by severity
    $script:WarnCount = 0
    $script:InfoCount = 0
    for ($i = 0; $i -lt $script:FindingSev.Count; $i++) {
        switch ($script:FindingSev[$i]) {
            'WARN' { $script:WarnCount++ }
            'INFO' { $script:InfoCount++ }
        }
    }

    Build-Recommendations

    # Pre-compute summary counts for renderers
    $script:CountPluginInstalled = @($script:PlgSrcs | Where-Object { $_ -eq 'installed' }).Count
    $script:CountPluginRemote    = @($script:PlgSrcs | Where-Object { $_ -eq 'remote' }).Count
    $script:CountPluginCached    = @($script:PlgSrcs | Where-Object { $_ -eq 'cached' }).Count
    $script:CountConnWeb         = @($script:ConnCats | Where-Object { $_ -eq 'web' }).Count
    $script:CountConnNotConn     = @($script:ConnCats | Where-Object { $_ -eq 'not_connected' }).Count
    $script:CountConnDesktop     = @($script:ConnCats | Where-Object { $_ -eq 'desktop' }).Count
}

# ── Main Execution ───────────────────────────────────────────────────────────

$userContexts = Get-UserContexts

$jsonMulti = ($script:OptJson -and @($userContexts).Count -gt 1)
if ($jsonMulti) { [Console]::Out.Write('[') }
$jsonFirst = $true

foreach ($ctx in $userContexts) {
    Invoke-Audit -Username $ctx.Username -HomeDir $ctx.HomeDir

    if ($script:OptJson) {
        if ($jsonMulti) {
            if (-not $jsonFirst) { [Console]::Out.Write(',') }
            $jsonFirst = $false
        }
        [Console]::Out.Write((Render-Json))
    }
    elseif ($script:OptHtml) {
        $safeUser = $ctx.Username -replace '[^a-zA-Z0-9_-]', ''
        $filename = $script:OptHtml
        if ($script:OptHtml -eq "AUTO") {
            $filename = "claude_audit_${safeUser}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        }
        elseif (@($userContexts).Count -gt 1) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($script:OptHtml)
            $ext  = [System.IO.Path]::GetExtension($script:OptHtml)
            $filename = "${base}_${safeUser}${ext}"
        }
        $htmlContent = Render-Html -Quiet $script:OptQuiet
        Write-HtmlReport -FilePath $filename -HtmlContent $htmlContent
        Write-Host "HTML report written to: $filename" -ForegroundColor Green
    }
    else {
        Render-Ascii -Quiet $script:OptQuiet
    }
}

if ($jsonMulti) { [Console]::Out.WriteLine(']') }

exit 0
