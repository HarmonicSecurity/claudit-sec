#!/bin/zsh
# CLAUDIT - Claude Desktop & Claude Code Security Audit Tool (Zsh)
# Read-only, single-file audit for macOS. Requires: zsh, jq, macOS.
setopt PIPE_FAIL KSH_ARRAYS BASH_REMATCH TYPESET_SILENT NULL_GLOB

VERSION="2.1.0"
CLAUDE_DESKTOP_DIR="Library/Application Support/Claude"
CLAUDE_CODE_DIR=".claude"
DANGEROUS_TOOLS="execute_javascript write_file edit_file run_command execute_sql"
DAY_NAMES=(Sunday Monday Tuesday Wednesday Thursday Friday Saturday)

# ── Preflight ────────────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "CLAUDIT requires macOS (Darwin). Detected: $(uname -s)" >&2; exit 1
fi
if ! command -v jq &>/dev/null; then
    echo "CLAUDIT requires jq. Install: brew install jq" >&2; exit 1
fi

# ── Global State ─────────────────────────────────────────────────────────────
TIMESTAMP="" ; HOSTNAME_VAL="" ; AUDIT_USER="" ; HOME_DIR=""

# Findings (parallel arrays)
FINDING_SEV=() ; FINDING_SECT=() ; FINDING_MSG=() ; FINDING_DET=()

# Desktop / Cowork prefs
declare -A DESKTOP_PREFS COWORK_PREFS APP_CONFIG RUNTIME_INFO COOKIES_INFO
declare -A EXT_SETTINGS_JSON  # ext_name -> raw json
COWORK_ENABLED_PLUGINS=() ; COWORK_NETWORK_MODE=""
declare -A COWORK_MARKETPLACES_JSON  # name -> json

# MCP Servers
MCP_NAMES=() ; MCP_CMDS=() ; MCP_ARGS_STR=() ; MCP_ENV_KEYS=()

# Plugins
PLG_NAMES=() ; PLG_VERS=() ; PLG_SRCS=() ; PLG_SCOPES=() ; PLG_AUTHORS=()
PLG_DESCS=() ; PLG_MPS=() ; PLG_INSTALLED_ATS=() ; PLG_INSTALLED_BYS=()
PLG_IDS=() ; PLG_SKILL_COUNTS=()
MARKETPLACE_AVAILABLE=()

# Connectors
CONN_NAMES=() ; CONN_CATS=() ; CONN_TOOLS=() ; CONN_TAGS=()

# Skills
SK_NAMES=() ; SK_DESCS=() ; SK_SRCS=() ; SK_PLUGINS=() ; SK_PATHS=()

# Scheduled Tasks
ST_IDS=() ; ST_CRONS=() ; ST_CRON_ENG=() ; ST_ENABLEDS=() ; ST_FPATHS=()
ST_CREATED=() ; ST_SNAMES=() ; ST_SDESCS=() ; ST_PROMPTS=()

# Extensions (DXT)
EXT_IDS=() ; EXT_NAMES=() ; EXT_VERS=() ; EXT_AUTHORS=() ; EXT_SIGNEDS=()
EXT_SIG_STATS=() ; EXT_TOOLS_STR=() ; EXT_DANGER_STR=() ; EXT_INST_ATS=()
EXT_DESCS=()

# File Permissions
FP_PATHS=() ; FP_MODES=() ; FP_STATS=()

# Blocklist / Code settings
BLOCKLIST_ENTRIES=0 ; BLOCKLIST_STATUS=""
CLAUDE_CODE_JSON="{}"

# Counters
WARN_COUNT=0 ; INFO_COUNT=0 ; CRITICAL_COUNT=0

# Session dirs found
SESSION_DIRS=()

# ── Utility Functions ────────────────────────────────────────────────────────
add_finding() { # sev sect msg [detail]
    FINDING_SEV+=("$1"); FINDING_SECT+=("$2"); FINDING_MSG+=("$3"); FINDING_DET+=("${4:-}")
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"; s="${s//\'/&#39;}"
    printf '%s' "$s"
}

truncate_str() { # str maxlen
    local s="$1" m="$2"
    if ((${#s} <= m)); then printf '%s' "$s"; else printf '%s...' "${s:0:$((m-3))}"; fi
}

JSON_ERROR=""
safe_read_json() { # _path -> stdout=json, sets JSON_ERROR
    local _path="$1"
    JSON_ERROR=""
    if [[ ! -e "$_path" ]]; then JSON_ERROR="ABSENT"; return 1; fi
    if [[ ! -r "$_path" ]]; then JSON_ERROR="PERMISSION_DENIED"; return 1; fi
    local raw
    raw=$(cat "$_path" 2>/dev/null) || { JSON_ERROR="READ_ERROR"; return 1; }
    local trimmed
    trimmed=$(printf '%s' "$raw" | tr -d '[:space:]')
    if [[ -z "$trimmed" ]]; then echo "{}"; return 0; fi
    local parsed
    parsed=$(printf '%s' "$raw" | jq -c '.' 2>/dev/null) || { JSON_ERROR="MALFORMED_JSON"; return 1; }
    printf '%s' "$parsed"
    return 0
}

safe_read_text() { # _path -> stdout=text, sets JSON_ERROR
    local _path="$1"; JSON_ERROR=""
    if [[ ! -e "$_path" ]]; then JSON_ERROR="ABSENT"; return 1; fi
    if [[ ! -r "$_path" ]]; then JSON_ERROR="PERMISSION_DENIED"; return 1; fi
    cat "$_path" 2>/dev/null || { JSON_ERROR="READ_ERROR"; return 1; }
}

get_file_permission() { # _path -> appends to FP arrays
    local _path="$1"
    [[ -e "$_path" ]] || return 0
    local mode_oct
    mode_oct=$(stat -f '%Lp' "$_path" 2>/dev/null) || return 0
    local mode_int
    mode_int=$((8#$mode_oct))
    local issues=()
    ((mode_int & 8#020)) && issues+=("group-writable")
    ((mode_int & 8#002)) && issues+=("world-writable")
    ((mode_int & 8#040)) && issues+=("group-readable")
    ((mode_int & 8#004)) && issues+=("world-readable")
    local perm_status="OK"
    if ((${#issues[@]} > 0)); then
        local has_write=false
        for iss in "${issues[@]}"; do [[ "$iss" == *writable* ]] && has_write=true; done
        local sev="WARN"; [[ "$has_write" == "true" ]] && sev="CRITICAL"
        local joined
        joined=$(IFS=', '; echo "${issues[*]}")
        perm_status="${sev}: ${joined}"
    fi
    FP_PATHS+=("$_path"); FP_MODES+=("$mode_oct"); FP_STATS+=("$perm_status")
}

fmt_bytes() {
    local n="$1"
    if ((n < 1024)); then echo "${n} B"
    elif ((n < 1048576)); then printf '%.1f KB' "$(echo "scale=1; $n/1024" | bc 2>/dev/null || echo 0)"
    elif ((n < 1073741824)); then printf '%.1f MB' "$(echo "scale=1; $n/1048576" | bc 2>/dev/null || echo 0)"
    else printf '%.1f GB' "$(echo "scale=1; $n/1073741824" | bc 2>/dev/null || echo 0)"
    fi
}

SKILL_FM_NAME="" ; SKILL_FM_DESC=""
parse_skill_frontmatter() { # file
    local file="$1"; SKILL_FM_NAME=""; SKILL_FM_DESC=""
    [[ -f "$file" && -r "$file" ]] || return 0
    local content
    content=$(cat "$file" 2>/dev/null) || return 0
    local first_line
    first_line=$(printf '%s' "$content" | head -1)
    [[ "$first_line" == "---"* ]] || return 0
    local fm
    fm=$(printf '%s' "$content" | sed -n '2,/^---/{/^---/!p;}')
    SKILL_FM_NAME=$(printf '%s' "$fm" | grep -m1 '^name:' | sed 's/^name:[[:space:]]*//' | sed "s/^[\"']//;s/[\"']$//")
    local desc_line
    desc_line=$(printf '%s' "$fm" | grep -m1 '^description:' | sed 's/^description:[[:space:]]*//')
    if [[ -z "$desc_line" || "$desc_line" == ">" || "$desc_line" == "|" ]]; then
        SKILL_FM_DESC=$(printf '%s' "$fm" | awk '
            /^description:/ { f=1; next }
            f && /^  / { sub(/^  /,""); d = d ? d " " $0 : $0; next }
            f && !/^  / { f=0 }
            END { print d }')
    else
        SKILL_FM_DESC=$(printf '%s' "$desc_line" | sed "s/^[\"']//;s/[\"']$//")
    fi
}

# ── Cron-to-English Parser ───────────────────────────────────────────────────
_fmt_time() { # hour minute
    local h=$1 m=$2
    if ((h == 0)); then printf '12:%02d AM' "$m"
    elif ((h < 12)); then printf '%d:%02d AM' "$h" "$m"
    elif ((h == 12)); then printf '12:%02d PM' "$m"
    else printf '%d:%02d PM' "$((h-12))" "$m"; fi
}

_parse_dow() { # dow_str
    local d="$1"
    [[ "$d" == "*" ]] && return 0
    [[ "$d" == "1-5" ]] && echo "Weekdays" && return 0
    [[ "$d" == "0-6" ]] && return 0
    if [[ "$d" =~ ^[0-6]$ ]]; then echo "${DAY_NAMES[$d]}"; return 0; fi
    if [[ "$d" == *,* ]]; then
        local parts=() names=()
        IFS=',' read -rA parts <<< "$d"
        for p in "${parts[@]}"; do
            [[ "$p" =~ ^[0-6]$ ]] && names+=("${DAY_NAMES[$p]}")
        done
        ((${#names[@]} > 0)) && { local IFS=', '; echo "${names[*]}"; return 0; }
    fi
    echo "$d"
}

cron_to_english() {
    local expr="$1"
    local -a parts
    read -rA parts <<< "$expr"
    ((${#parts[@]} == 5)) || { echo "$expr"; return; }
    local minute="${parts[0]}" hour="${parts[1]}" dom="${parts[2]}" month="${parts[3]}" dow="${parts[4]}"

    if [[ "$minute" == "*" && "$hour" == "*" && "$dom" == "*" && "$month" == "*" && "$dow" == "*" ]]; then
        echo "Every minute"; return; fi
    if [[ "$minute" == "*/"* && "$hour" == "*" && "$dom" == "*" && "$month" == "*" && "$dow" == "*" ]]; then
        local n="${minute#*/}"
        [[ "$n" =~ ^[0-9]+$ ]] && { ((n==1)) && echo "Every minute" || echo "Every $n minutes"; return; }
    fi
    if [[ "$minute" == "0" && "$hour" == "*/"* && "$dom" == "*" && "$month" == "*" && "$dow" == "*" ]]; then
        local n="${hour#*/}"
        [[ "$n" =~ ^[0-9]+$ ]] && { ((n==1)) && echo "Every hour" || echo "Every $n hours"; return; }
    fi
    if [[ "$minute" == "0" && "$hour" == "*" && "$dom" == "*" && "$month" == "*" && "$dow" == "*" ]]; then
        echo "Every hour"; return; fi
    if [[ "$hour" == "*" && "$dom" == "*" && "$month" == "*" && "$dow" == "*" ]]; then
        [[ "$minute" =~ ^[0-9]+$ ]] && { printf 'Every hour at :%02d\n' "$minute"; return; }
    fi
    [[ "$minute" =~ ^[0-9]+$ && "$hour" =~ ^[0-9]+$ ]] || { echo "$expr"; return; }
    local m=$((10#$minute)) h=$((10#$hour))
    local time_str; time_str=$(_fmt_time "$h" "$m")
    if [[ "$dom" != "*" && "$month" == "*" && "$dow" == "*" ]]; then
        [[ "$dom" =~ ^[0-9]+$ ]] && { echo "Monthly on day $dom at $time_str"; return; }
        echo "$expr"; return
    fi
    if [[ "$dom" == "*" && "$month" == "*" ]]; then
        if [[ "$dow" == "*" ]]; then echo "Daily at $time_str"; return; fi
        if [[ "$dow" == "1-5" ]]; then echo "Weekdays at $time_str"; return; fi
        local day_name; day_name=$(_parse_dow "$dow")
        [[ -n "$day_name" ]] && { echo "Weekly on $day_name at $time_str"; return; }
    fi
    echo "$expr"
}

# ── User Context Detection ───────────────────────────────────────────────────
VALID_USER_RE='^[a-zA-Z0-9._-]+$'

detect_user_contexts() { # sets USER_CONTEXTS array of "user|home" pairs
    USER_CONTEXTS=()
    if [[ -n "${OPT_USER:-}" ]]; then
        if [[ ! "$OPT_USER" =~ $VALID_USER_RE ]] || [[ "$OPT_USER" == "." || "$OPT_USER" == ".." ]]; then
            echo "Invalid username: '$OPT_USER'." >&2; exit 1
        fi
        USER_CONTEXTS+=("$OPT_USER|/Users/$OPT_USER"); return
    fi
    if [[ "${OPT_ALL_USERS:-false}" == "true" ]]; then
        local dscl_out
        dscl_out=$(dscl . -list /Users UniqueID 2>/dev/null) || true
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local uname uid_str
            uname=$(printf '%s\n' "$line" | awk '{print $1}')
            uid_str=$(printf '%s\n' "$line" | awk '{print $NF}')
            [[ "$uid_str" =~ ^[0-9]+$ ]] || continue
            local uid=$((10#$uid_str))
            ((uid >= 500)) || continue
            [[ "$uname" == _* ]] && continue
            local uhome="/Users/$uname"
            if [[ -d "$uhome/$CLAUDE_DESKTOP_DIR" || -d "$uhome/$CLAUDE_CODE_DIR" ]]; then
                USER_CONTEXTS+=("$uname|$uhome")
            fi
        done <<< "$dscl_out"
        if ((${#USER_CONTEXTS[@]} == 0)); then
            echo "No users with Claude data found." >&2; exit 1
        fi
        return
    fi
    # When running as root (e.g. via MDM/FleetDM), default to all-users scan
    if [[ "$(id -u)" == "0" ]]; then
        OPT_ALL_USERS="true"
        detect_user_contexts
        return
    fi
    local cur_user="${USER:-unknown}" cur_home="${HOME:-/Users/$cur_user}"
    USER_CONTEXTS+=("$cur_user|$cur_home")
}

# ── Session Directory Detection ──────────────────────────────────────────────
find_session_dirs() { # claude_dir
    local claude_dir="$1"; SESSION_DIRS=()
    local sessions_dir="$claude_dir/local-agent-mode-sessions"
    [[ -d "$sessions_dir" ]] || return 0
    local org_dir
    for org_dir in "$sessions_dir"/*/; do
        [[ -d "$org_dir" ]] || continue
        [[ "$(basename "$org_dir")" == .* ]] && continue
        local user_dir
        for user_dir in "$org_dir"*/; do
            [[ -d "$user_dir" ]] || continue
            [[ "$(basename "$user_dir")" == .* ]] && continue
            SESSION_DIRS+=("${user_dir%/}")
        done
    done
}

# ── Data Collection ──────────────────────────────────────────────────────────
collect_desktop_settings() { # claude_dir
    local claude_dir="$1"
    local config_path="$claude_dir/claude_desktop_config.json"
    local data
    data=$(safe_read_json "$config_path") || true
    if [[ -n "$JSON_ERROR" ]]; then
        add_finding "INFO" "Desktop Settings" "claude_desktop_config.json: [$JSON_ERROR]"
        return
    fi
    [[ -z "$data" || "$data" == "null" ]] && return

    local prefs
    prefs=$(printf '%s' "$data" | jq -c '.preferences // {}')
    DESKTOP_PREFS[keepAwakeEnabled]=$(printf '%s' "$prefs" | jq -r '.keepAwakeEnabled // false')
    DESKTOP_PREFS[menuBarEnabled]=$(printf '%s' "$prefs" | jq -r '.menuBarEnabled // false')
    DESKTOP_PREFS[sidebarMode]=$(printf '%s' "$prefs" | jq -r '.sidebarMode // ""')
    DESKTOP_PREFS[quickEntryShortcut]=$(printf '%s' "$prefs" | jq -r '.quickEntryShortcut // ""')

    if [[ "${DESKTOP_PREFS[keepAwakeEnabled]}" == "true" ]]; then
        add_finding "WARN" "Desktop Settings" "keepAwakeEnabled is ON — prevents macOS from sleeping" "keepAwakeEnabled=true"
    fi

    COWORK_PREFS[coworkScheduledTasksEnabled]=$(printf '%s' "$prefs" | jq -r '.coworkScheduledTasksEnabled // false')
    COWORK_PREFS[ccdScheduledTasksEnabled]=$(printf '%s' "$prefs" | jq -r '.ccdScheduledTasksEnabled // false')
    COWORK_PREFS[coworkWebSearchEnabled]=$(printf '%s' "$prefs" | jq -r '.coworkWebSearchEnabled // false')

    [[ "${COWORK_PREFS[coworkScheduledTasksEnabled]}" == "true" ]] && \
        add_finding "WARN" "Cowork Settings" "Scheduled tasks ENABLED — autonomous task execution active" "coworkScheduledTasksEnabled=true"
    [[ "${COWORK_PREFS[ccdScheduledTasksEnabled]}" == "true" ]] && \
        add_finding "WARN" "Cowork Settings" "Code Desktop scheduled tasks ENABLED" "ccdScheduledTasksEnabled=true"
    [[ "${COWORK_PREFS[coworkWebSearchEnabled]}" == "true" ]] && \
        add_finding "WARN" "Cowork Settings" "Web search ENABLED — autonomous internet access" "coworkWebSearchEnabled=true"

    # MCP Servers
    local mcp_json
    mcp_json=$(printf '%s' "$data" | jq -c '.mcpServers // {}')
    if [[ "$mcp_json" != "{}" && "$mcp_json" != "null" ]]; then
        local srv_names
        srv_names=$(printf '%s' "$mcp_json" | jq -r 'keys[]' 2>/dev/null) || true
        while IFS= read -r sname; do
            [[ -z "$sname" ]] && continue
            local srv_data
            srv_data=$(printf '%s' "$mcp_json" | jq -c --arg n "$sname" '.[$n]')
            local cmd args_str env_keys
            cmd=$(printf '%s' "$srv_data" | jq -r '.command // "[unknown]"')
            args_str=$(printf '%s' "$srv_data" | jq -r '(.args // []) | map(if test("(sk-|key=|token=|secret=|password=)";"i") then "[REDACTED]" else . end) | join(" ")')
            env_keys=$(printf '%s' "$srv_data" | jq -r '.env // {} | keys | join(", ")')
            [[ -z "$env_keys" ]] && env_keys="-"
            MCP_NAMES+=("$sname"); MCP_CMDS+=("$cmd"); MCP_ARGS_STR+=("$args_str"); MCP_ENV_KEYS+=("$env_keys")
        done <<< "$srv_names"
    fi
    get_file_permission "$config_path"
}

collect_cowork_settings() { # uses SESSION_DIRS
    local sess_dir
    for sess_dir in "${SESSION_DIRS[@]}"; do
        local cs_path="$sess_dir/cowork_settings.json"
        local data
        data=$(safe_read_json "$cs_path") || true
        [[ -n "$JSON_ERROR" || -z "$data" || "$data" == "null" ]] && continue

        local ep_keys
        ep_keys=$(printf '%s' "$data" | jq -r '.enabledPlugins // {} | to_entries[] | select(.value == true) | .key' 2>/dev/null) || true
        while IFS= read -r k; do
            [[ -n "$k" ]] && COWORK_ENABLED_PLUGINS+=("$k")
        done <<< "$ep_keys"

        local mp_keys
        mp_keys=$(printf '%s' "$data" | jq -r '.extraKnownMarketplaces // {} | keys[]' 2>/dev/null) || true
        while IFS= read -r mk; do
            [[ -z "$mk" ]] && continue
            COWORK_MARKETPLACES_JSON["$mk"]=$(printf '%s' "$data" | jq -c --arg k "$mk" '.extraKnownMarketplaces[$k]')
        done <<< "$mp_keys"
    done
}

collect_app_config() { # claude_dir
    local claude_dir="$1"
    local config_path="$claude_dir/config.json"
    local data
    data=$(safe_read_json "$config_path") || true
    if [[ -n "$JSON_ERROR" ]]; then
        [[ "$JSON_ERROR" != "ABSENT" ]] && add_finding "INFO" "App Config" "config.json: [$JSON_ERROR]"
        return
    fi
    [[ -z "$data" || "$data" == "null" ]] && return

    local nm
    nm=$(printf '%s' "$data" | jq -r '.coworkNetworkMode // ""')
    if [[ -n "$nm" ]]; then
        COWORK_NETWORK_MODE="$nm"; APP_CONFIG[coworkNetworkMode]="$nm"
    fi

    local has_oauth
    has_oauth=$(printf '%s' "$data" | jq -r 'has("oauth:tokenCache") and (.["oauth:tokenCache"] | length > 0)')
    if [[ "$has_oauth" == "true" ]]; then
        add_finding "WARN" "Security" "Unencrypted OAuth token in plaintext config" "oauth:tokenCache present in config.json"
        APP_CONFIG["oauth:tokenCache"]="[REDACTED]"
    fi

    local dxt_keys
    dxt_keys=$(printf '%s' "$data" | jq -r 'keys[] | select(contains("dxt:allowlistEnabled"))' 2>/dev/null) || true
    while IFS= read -r dk; do
        [[ -z "$dk" ]] && continue
        local val
        val=$(printf '%s' "$data" | jq -r --arg k "$dk" '.[$k]')
        APP_CONFIG["$dk"]="$val"
        [[ "$val" == "false" ]] && add_finding "WARN" "Security" "Extension allowlist DISABLED: $dk" "Any extension can be installed without approval"
    done <<< "$dxt_keys"

    local ant_did
    ant_did=$(printf '%s' "$data" | jq -r '.["ant-did"] // ""')
    if [[ -n "$ant_did" ]]; then
        RUNTIME_INFO[ant_did]="$ant_did"; APP_CONFIG["ant-did"]="$ant_did"
    fi
    get_file_permission "$config_path"
}

collect_extensions() { # claude_dir
    local claude_dir="$1"
    local ext_path="$claude_dir/extensions-installations.json"
    local data
    data=$(safe_read_json "$ext_path") || true
    if [[ -n "$JSON_ERROR" ]]; then
        [[ "$JSON_ERROR" != "ABSENT" ]] && add_finding "INFO" "Extensions" "extensions-installations.json: [$JSON_ERROR]"
        return
    fi
    [[ -z "$data" || "$data" == "null" ]] && return

    local ext_json
    ext_json=$(printf '%s' "$data" | jq -c 'if .extensions then .extensions else . end')
    local ext_type
    ext_type=$(printf '%s' "$ext_json" | jq -r 'type')

    local ext_array="[]"
    if [[ "$ext_type" == "array" ]]; then ext_array="$ext_json"
    elif [[ "$ext_type" == "object" ]]; then ext_array=$(printf '%s' "$ext_json" | jq -c '[.[] | select(type == "object")]')
    fi

    local count
    count=$(printf '%s' "$ext_array" | jq 'length')
    local i
    for ((i=0; i<count; i++)); do
        local e
        e=$(printf '%s' "$ext_array" | jq -c ".[$i]")
        local eid eversion einst_at ename edesc eauthor
        eid=$(printf '%s' "$e" | jq -r '.id // "unknown"')
        eversion=$(printf '%s' "$e" | jq -r '.version // "?"')
        einst_at=$(printf '%s' "$e" | jq -r '.installedAt // ""')
        ename=$(printf '%s' "$e" | jq -r '.manifest.display_name // .manifest.name // .id // "unknown"')
        edesc=$(printf '%s' "$e" | jq -r '.manifest.description // ""')
        eauthor=$(printf '%s' "$e" | jq -r 'if .manifest.author | type == "object" then .manifest.author.name // "" else .manifest.author // "" end')
        local esig_status esigned
        esig_status=$(printf '%s' "$e" | jq -r '.signatureInfo.status // "unsigned"')
        esigned="false"; [[ "$esig_status" != "unsigned" ]] && esigned="true"

        local tools_str="" danger_str=""
        local tool_names
        tool_names=$(printf '%s' "$e" | jq -r '.manifest.tools // [] | .[] | if type == "object" then .name // "" else . end' 2>/dev/null) || true
        local tools_arr=() danger_arr=()
        while IFS= read -r tn; do
            [[ -z "$tn" ]] && continue
            tools_arr+=("$tn")
            [[ " $DANGEROUS_TOOLS " == *" $tn "* ]] && danger_arr+=("$tn")
        done <<< "$tool_names"
        tools_str=$(IFS=','; echo "${tools_arr[*]}")
        danger_str=$(IFS=','; echo "${danger_arr[*]}")

        EXT_IDS+=("$eid"); EXT_NAMES+=("$ename"); EXT_VERS+=("$eversion")
        EXT_AUTHORS+=("$eauthor"); EXT_SIGNEDS+=("$esigned"); EXT_SIG_STATS+=("$esig_status")
        EXT_TOOLS_STR+=("$tools_str"); EXT_DANGER_STR+=("$danger_str")
        EXT_INST_ATS+=("$einst_at"); EXT_DESCS+=("$edesc")

        [[ "$esigned" == "false" ]] && add_finding "WARN" "Extensions" "Unsigned extension: $ename" "version=$eversion"
        [[ -n "$danger_str" ]] && add_finding "WARN" "Extensions" "Extension '$ename' has dangerous tools: ${danger_str//,/, }"
    done
    get_file_permission "$ext_path"
}

collect_extension_settings() { # claude_dir
    local claude_dir="$1"
    local settings_dir="$claude_dir/Claude Extensions Settings"
    [[ -d "$settings_dir" ]] || return 0
    local sf
    for sf in "$settings_dir"/*.json; do
        [[ -f "$sf" ]] || continue
        local data
        data=$(safe_read_json "$sf") || true
        [[ -n "$JSON_ERROR" || -z "$data" ]] && continue
        local ext_name
        ext_name=$(basename "$sf" .json)
        EXT_SETTINGS_JSON["$ext_name"]="$data"
        get_file_permission "$sf"
    done
}

collect_plugins() { # uses SESSION_DIRS
    local -A installed_names remote_names
    local sess_dir
    for sess_dir in "${SESSION_DIRS[@]}"; do
        # a) Installed plugins
        local ip_path="$sess_dir/cowork_plugins/installed_plugins.json"
        local ip_data
        ip_data=$(safe_read_json "$ip_path") || true
        if [[ -z "$JSON_ERROR" && -n "$ip_data" && "$ip_data" != "null" ]]; then
            local pkeys
            pkeys=$(printf '%s' "$ip_data" | jq -r '.plugins // {} | keys[]' 2>/dev/null) || true
            while IFS= read -r pkey; do
                [[ -z "$pkey" ]] && continue
                local name_part="${pkey%%@*}" mp_part=""
                [[ "$pkey" == *@* ]] && mp_part="${pkey#*@}"
                local entries
                entries=$(printf '%s' "$ip_data" | jq -c --arg k "$pkey" '.plugins[$k]')
                local etype
                etype=$(printf '%s' "$entries" | jq -r 'type')
                [[ "$etype" != "array" ]] && entries="[$entries]"
                local ecount
                ecount=$(printf '%s' "$entries" | jq 'length')
                local j
                for ((j=0; j<ecount; j++)); do
                    local entry
                    entry=$(printf '%s' "$entries" | jq -c ".[$j]")
                    [[ "$(printf '%s' "$entry" | jq -r 'type')" != "object" ]] && continue
                    local pver pscope pinst_at install_path pauthor pdesc
                    pver=$(printf '%s' "$entry" | jq -r '.version // "?"')
                    pscope=$(printf '%s' "$entry" | jq -r '.scope // ""')
                    pinst_at=$(printf '%s' "$entry" | jq -r '.installedAt // ""')
                    install_path=$(printf '%s' "$entry" | jq -r '.installPath // ""')
                    pauthor=""; pdesc=""
                    if [[ -n "$install_path" ]]; then
                        local pj_path="$install_path/.claude-plugin/plugin.json"
                        local pj_data
                        pj_data=$(safe_read_json "$pj_path") || true
                        if [[ -z "$JSON_ERROR" && -n "$pj_data" ]]; then
                            pauthor=$(printf '%s' "$pj_data" | jq -r 'if .author | type == "object" then .author.name // "" else .author // "" end')
                            pdesc=$(printf '%s' "$pj_data" | jq -r '.description // ""')
                        fi
                    fi
                    local sk_count=0
                    if [[ -n "$install_path" && -d "$install_path/skills" ]]; then
                        sk_count=$(find "$install_path/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
                    fi
                    PLG_NAMES+=("$name_part"); PLG_VERS+=("$pver"); PLG_SRCS+=("installed")
                    PLG_SCOPES+=("$pscope"); PLG_AUTHORS+=("$pauthor"); PLG_DESCS+=("$pdesc")
                    PLG_MPS+=("$mp_part"); PLG_INSTALLED_ATS+=("$pinst_at"); PLG_INSTALLED_BYS+=("")
                    PLG_IDS+=(""); PLG_SKILL_COUNTS+=("$sk_count")
                    installed_names["$name_part"]=1
                done
            done <<< "$pkeys"
        fi

        # b) Remote plugins
        local remote_dir="$sess_dir/remote_cowork_plugins"
        local manifest_path="$remote_dir/manifest.json"
        local manifest_data
        manifest_data=$(safe_read_json "$manifest_path") || true
        if [[ -z "$JSON_ERROR" && -n "$manifest_data" && "$manifest_data" != "null" ]]; then
            local rp_count
            rp_count=$(printf '%s' "$manifest_data" | jq '.plugins // [] | length')
            local ri
            for ((ri=0; ri<rp_count; ri++)); do
                local rp
                rp=$(printf '%s' "$manifest_data" | jq -c ".plugins[$ri]")
                [[ "$(printf '%s' "$rp" | jq -r 'type')" != "object" ]] && continue
                local rp_id rp_name rp_mp rp_by
                rp_id=$(printf '%s' "$rp" | jq -r '.id // ""')
                rp_name=$(printf '%s' "$rp" | jq -r '.name // ""')
                rp_mp=$(printf '%s' "$rp" | jq -r '.marketplaceName // ""')
                rp_by=$(printf '%s' "$rp" | jq -r '.installedBy // ""')
                local rp_ver="" rp_author="" rp_desc=""
                local rp_pj_path="$remote_dir/$rp_id/.claude-plugin/plugin.json"
                local rp_pj
                rp_pj=$(safe_read_json "$rp_pj_path") || true
                if [[ -z "$JSON_ERROR" && -n "$rp_pj" ]]; then
                    rp_ver=$(printf '%s' "$rp_pj" | jq -r '.version // ""')
                    rp_author=$(printf '%s' "$rp_pj" | jq -r 'if .author | type == "object" then .author.name // "" else .author // "" end')
                    rp_desc=$(printf '%s' "$rp_pj" | jq -r '.description // ""')
                fi
                local rp_sk=0
                [[ -d "$remote_dir/$rp_id/skills" ]] && rp_sk=$(find "$remote_dir/$rp_id/skills" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')

                PLG_NAMES+=("$rp_name"); PLG_VERS+=("$rp_ver"); PLG_SRCS+=("remote")
                PLG_SCOPES+=(""); PLG_AUTHORS+=("$rp_author"); PLG_DESCS+=("$rp_desc")
                PLG_MPS+=("$rp_mp"); PLG_INSTALLED_ATS+=(""); PLG_INSTALLED_BYS+=("$rp_by")
                PLG_IDS+=("$rp_id"); PLG_SKILL_COUNTS+=("$rp_sk")
                remote_names["$rp_name"]=1
                add_finding "REVIEW" "Plugins" "Remote plugin: $rp_name (v$rp_ver) deployed by $rp_by" "id=$rp_id, marketplace=$rp_mp"
            done
        fi

        # c) Marketplace catalog
        local mp_base="$sess_dir/cowork_plugins/marketplaces"
        if [[ -d "$mp_base" ]]; then
            local mp_dir
            for mp_dir in "$mp_base"/*/; do
                [[ -d "$mp_dir" ]] || continue
                [[ "$(basename "$mp_dir")" == .* ]] && continue
                local plugin_dir
                for plugin_dir in "$mp_dir"*/; do
                    [[ -d "$plugin_dir" ]] || continue
                    [[ "$(basename "$plugin_dir")" == .* ]] && continue
                    local pname
                    pname=$(basename "$plugin_dir")
                    if [[ -f "$plugin_dir/.claude-plugin/plugin.json" ]]; then
                        [[ -z "${installed_names[$pname]:-}" && -z "${remote_names[$pname]:-}" ]] && MARKETPLACE_AVAILABLE+=("$pname")
                    else
                        local sub
                        for sub in "$plugin_dir"*/; do
                            [[ -d "$sub" && "$(basename "$sub")" != .* ]] || continue
                            if [[ -f "$sub/.claude-plugin/plugin.json" ]]; then
                                local sname; sname=$(basename "$sub")
                                [[ -z "${installed_names[$sname]:-}" && -z "${remote_names[$sname]:-}" ]] && MARKETPLACE_AVAILABLE+=("$sname")
                            fi
                        done
                    fi
                done
            done
        fi

        # d) Cache
        local cache_base="$sess_dir/cowork_plugins/cache"
        if [[ -d "$cache_base" ]]; then
            local cmp_dir
            for cmp_dir in "$cache_base"/*/; do
                [[ -d "$cmp_dir" ]] || continue
                local cpd
                for cpd in "$cmp_dir"*/; do
                    [[ -d "$cpd" ]] || continue
                    local cpname; cpname=$(basename "$cpd")
                    [[ -z "${installed_names[$cpname]:-}" && -z "${remote_names[$cpname]:-}" ]] || continue
                    local latest_ver
                    latest_ver=$(ls -1d "$cpd"*/ 2>/dev/null | sort -t. -k1,1rn -k2,2rn -k3,3rn | head -1)
                    [[ -n "$latest_ver" && -f "$latest_ver/.claude-plugin/plugin.json" ]] || continue
                    local cpj
                    cpj=$(safe_read_json "$latest_ver/.claude-plugin/plugin.json") || true
                    [[ -z "$JSON_ERROR" && -n "$cpj" ]] || continue
                    local cn cv ca cd
                    cn=$(printf '%s' "$cpj" | jq -r '.name // ""'); [[ -z "$cn" ]] && cn="$cpname"
                    cv=$(printf '%s' "$cpj" | jq -r '.version // ""')
                    ca=$(printf '%s' "$cpj" | jq -r 'if .author | type == "object" then .author.name // "" else .author // "" end')
                    cd=$(printf '%s' "$cpj" | jq -r '.description // ""')
                    PLG_NAMES+=("$cn"); PLG_VERS+=("$cv"); PLG_SRCS+=("cached")
                    PLG_SCOPES+=(""); PLG_AUTHORS+=("$ca"); PLG_DESCS+=("$cd")
                    PLG_MPS+=("$(basename "$cmp_dir")"); PLG_INSTALLED_ATS+=(""); PLG_INSTALLED_BYS+=("")
                    PLG_IDS+=(""); PLG_SKILL_COUNTS+=("0")
                done
            done
        fi
    done
    # Deduplicate marketplace available
    local -A mp_seen; local mp_dedup=()
    local mp_item
    for mp_item in "${MARKETPLACE_AVAILABLE[@]}"; do
        [[ -z "${mp_seen[$mp_item]:-}" ]] && { mp_dedup+=("$mp_item"); mp_seen["$mp_item"]=1; }
    done
    MARKETPLACE_AVAILABLE=("${mp_dedup[@]+"${mp_dedup[@]}"}")
}

collect_connectors() { # uses SESSION_DIRS, EXT_*, MCP_*
    local -A best_ts best_conn_json
    local sess_dir
    for sess_dir in "${SESSION_DIRS[@]}"; do
        local entry
        for entry in "$sess_dir"/local_*.json; do
            [[ -f "$entry" ]] || continue
            local data
            data=$(safe_read_json "$entry") || true
            [[ -n "$JSON_ERROR" || -z "$data" ]] && continue
            local ts rmc_len
            ts=$(printf '%s' "$data" | jq -r '.lastActivityAt // 0')
            rmc_len=$(printf '%s' "$data" | jq '.remoteMcpServersConfig // [] | length')
            ((rmc_len > 0)) || continue
            local si
            for ((si=0; si<rmc_len; si++)); do
                local srv_name srv_json
                srv_name=$(printf '%s' "$data" | jq -r ".remoteMcpServersConfig[$si].name // \"\"")
                [[ -z "$srv_name" ]] && continue
                local key="${(L)srv_name}"  # lowercase
                if [[ -z "${best_ts[$key]:-}" ]] || ((ts > best_ts[$key])); then
                    best_ts["$key"]="$ts"
                    best_conn_json["$key"]="$srv_name|$(printf '%s' "$data" | jq -r ".remoteMcpServersConfig[$si].tools // [] | length")"
                fi
            done
        done
    done
    local -A seen_web_norm
    if ((${#best_conn_json[@]} > 0)); then
        local key
        while IFS= read -r key; do
            [[ -z "$key" ]] && continue
            local val="${best_conn_json[$key]}"
            local cname="${val%%|*}" ctc="${val#*|}"
            CONN_NAMES+=("$cname"); CONN_CATS+=("web"); CONN_TOOLS+=("$ctc"); CONN_TAGS+=("")
            local norm; norm=$(printf '%s' "$cname" | tr '[:upper:]' '[:lower:]' | tr ' _' '--' | tr -cd 'a-z0-9-')
            [[ -n "$norm" ]] && seen_web_norm["$norm"]=1
        done < <(printf '%s\n' "${(k)best_conn_json[@]}" | sort)
    fi

    # Not connected
    local -A not_connected
    for sess_dir in "${SESSION_DIRS[@]}"; do
        local remote_dir="$sess_dir/remote_cowork_plugins"
        [[ -d "$remote_dir" ]] || continue
        local mf_data
        mf_data=$(safe_read_json "$remote_dir/manifest.json") || true
        [[ -n "$JSON_ERROR" || -z "$mf_data" ]] && continue
        local rp_count
        rp_count=$(printf '%s' "$mf_data" | jq '.plugins // [] | length')
        local ri
        for ((ri=0; ri<rp_count; ri++)); do
            local pid
            pid=$(printf '%s' "$mf_data" | jq -r ".plugins[$ri].id // \"\"")
            [[ -z "$pid" ]] && continue
            local mcp_path="$remote_dir/$pid/.mcp.json"
            local mcp_data
            mcp_data=$(safe_read_json "$mcp_path") || true
            [[ -n "$JSON_ERROR" || -z "$mcp_data" ]] && continue
            local srv_names
            srv_names=$(printf '%s' "$mcp_data" | jq -r '.mcpServers // {} | keys[]' 2>/dev/null) || true
            while IFS= read -r sn; do
                [[ -z "$sn" ]] && continue
                local norm; norm=$(printf '%s' "$sn" | tr '[:upper:]' '[:lower:]' | tr ' _' '--' | tr -cd 'a-z0-9-')
                [[ -z "${seen_web_norm[$norm]:-}" ]] && not_connected["$norm"]="$sn"
            done <<< "$srv_names"
        done
    done
    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        CONN_NAMES+=("${not_connected[$key]}"); CONN_CATS+=("not_connected"); CONN_TOOLS+=("0"); CONN_TAGS+=("")
    done < <(printf '%s\n' "${(k)not_connected[@]}" | sort)

    # Desktop connectors from extensions
    local i
    for ((i=0; i<${#EXT_NAMES[@]}; i++)); do
        local tags=""
        [[ "${EXT_SIGNEDS[$i]}" == "false" ]] && tags="unsigned"
        CONN_NAMES+=("${EXT_NAMES[$i]}"); CONN_CATS+=("desktop")
        local tc; IFS=',' read -rA _t <<< "${EXT_TOOLS_STR[$i]}"; tc=${#_t[@]}; [[ -z "${EXT_TOOLS_STR[$i]}" ]] && tc=0
        CONN_TOOLS+=("$tc"); CONN_TAGS+=("$tags")
    done
    for ((i=0; i<${#MCP_NAMES[@]}; i++)); do
        CONN_NAMES+=("${MCP_NAMES[$i]}"); CONN_CATS+=("desktop"); CONN_TOOLS+=("0"); CONN_TAGS+=("LOCAL DEV")
    done

    local web_count=0 wn
    for ((i=0; i<${#CONN_CATS[@]}; i++)); do [[ "${CONN_CATS[$i]}" == "web" ]] && ((web_count++)); done
    local web_names=""
    for ((i=0; i<${#CONN_CATS[@]}; i++)); do
        [[ "${CONN_CATS[$i]}" == "web" ]] && { [[ -n "$web_names" ]] && web_names+=", "; web_names+="${CONN_NAMES[$i]}"; }
    done
    ((web_count > 0)) && add_finding "INFO" "Connectors" "$web_count web connector(s) authenticated: $web_names"
}

collect_skills() { # uses SESSION_DIRS, home
    local home="$1"
    # User-created skills
    local sched_dir="$home/Documents/Claude/Scheduled"
    if [[ -d "$sched_dir" ]]; then
        local skill_dir
        for skill_dir in "$sched_dir"/*/; do
            [[ -d "$skill_dir" ]] || continue
            local skill_md="$skill_dir/SKILL.md"
            [[ -f "$skill_md" ]] || continue
            parse_skill_frontmatter "$skill_md"
            local sn="${SKILL_FM_NAME:-$(basename "$skill_dir")}"
            SK_NAMES+=("$sn"); SK_DESCS+=("$SKILL_FM_DESC"); SK_SRCS+=("user"); SK_PLUGINS+=(""); SK_PATHS+=("$skill_md")
        done
    fi
    # Cowork skills-plugin: local-agent-mode-sessions/skills-plugin/<id>/<id>/skills/<skill>/SKILL.md
    local sp_base="$home/$CLAUDE_DESKTOP_DIR/local-agent-mode-sessions/skills-plugin"
    if [[ -d "$sp_base" ]]; then
        local sp_id1 sp_id2 sp_sk_dir
        for sp_id1 in "$sp_base"/*/; do
            [[ -d "$sp_id1" ]] || continue
            for sp_id2 in "$sp_id1"*/; do
                [[ -d "$sp_id2" ]] || continue
                [[ -d "$sp_id2/skills" ]] || continue
                for sp_sk_dir in "$sp_id2/skills"/*/; do
                    [[ -d "$sp_sk_dir" ]] || continue
                    local skill_md="$sp_sk_dir/SKILL.md"
                    [[ -f "$skill_md" ]] || continue
                    parse_skill_frontmatter "$skill_md"
                    local sn="${SKILL_FM_NAME:-$(basename "$sp_sk_dir")}"
                    # Dedup
                    local dup=false; local si
                    for ((si=0; si<${#SK_NAMES[@]}; si++)); do [[ "${SK_NAMES[$si]}" == "$sn" ]] && dup=true && break; done
                    [[ "$dup" == "true" ]] && continue
                    SK_NAMES+=("$sn"); SK_DESCS+=("$SKILL_FM_DESC"); SK_SRCS+=("user"); SK_PLUGINS+=(""); SK_PATHS+=("$skill_md")
                done
            done
        done
    fi
    # Alt skills dir
    local alt_skills="$home/.skills/skills"
    if [[ -d "$alt_skills" ]]; then
        local skill_dir
        for skill_dir in "$alt_skills"/*/; do
            [[ -d "$skill_dir" ]] || continue
            local skill_md="$skill_dir/SKILL.md"
            [[ -f "$skill_md" ]] || continue
            parse_skill_frontmatter "$skill_md"
            local sn="${SKILL_FM_NAME:-$(basename "$skill_dir")}"
            # Dedup check
            local dup=false; local si
            for ((si=0; si<${#SK_NAMES[@]}; si++)); do [[ "${SK_NAMES[$si]}" == "$sn" ]] && dup=true && break; done
            [[ "$dup" == "true" ]] && continue
            SK_NAMES+=("$sn"); SK_DESCS+=("$SKILL_FM_DESC"); SK_SRCS+=("user"); SK_PLUGINS+=(""); SK_PATHS+=("$skill_md")
        done
    fi
    # Claude Code user skills: ~/.claude/skills/<skill>/SKILL.md
    local cc_skills="$home/$CLAUDE_CODE_DIR/skills"
    if [[ -d "$cc_skills" ]]; then
        local skill_dir
        for skill_dir in "$cc_skills"/*/; do
            [[ -d "$skill_dir" ]] || continue
            local skill_md="$skill_dir/SKILL.md"
            [[ -f "$skill_md" ]] || continue
            parse_skill_frontmatter "$skill_md"
            local sn="${SKILL_FM_NAME:-$(basename "$skill_dir")}"
            local dup=false; local si
            for ((si=0; si<${#SK_NAMES[@]}; si++)); do [[ "${SK_NAMES[$si]}" == "$sn" ]] && dup=true && break; done
            [[ "$dup" == "true" ]] && continue
            SK_NAMES+=("$sn"); SK_DESCS+=("$SKILL_FM_DESC"); SK_SRCS+=("user"); SK_PLUGINS+=(""); SK_PATHS+=("$skill_md")
        done
    fi
    # Claude Code marketplace plugin skills: ~/.claude/plugins/marketplaces/<mp>/{plugins,external_plugins}/<plugin>/skills/<skill>/SKILL.md
    local cc_mp="$home/$CLAUDE_CODE_DIR/plugins/marketplaces"
    if [[ -d "$cc_mp" ]]; then
        local smd
        while IFS= read -r smd; do
            [[ -f "$smd" ]] || continue
            local sk_parent="${smd%/SKILL.md}"
            local sk_name="$(basename "$sk_parent")"
            local plugin_parent="${sk_parent%/skills/*}"
            local plugin_name="$(basename "$plugin_parent")"
            parse_skill_frontmatter "$smd"
            local sn="${SKILL_FM_NAME:-$sk_name}"
            local dup=false; local si
            for ((si=0; si<${#SK_NAMES[@]}; si++)); do [[ "${SK_NAMES[$si]}" == "$sn" ]] && dup=true && break; done
            [[ "$dup" == "true" ]] && continue
            SK_NAMES+=("$sn"); SK_DESCS+=("$SKILL_FM_DESC")
            SK_SRCS+=("plugin"); SK_PLUGINS+=("$plugin_name"); SK_PATHS+=("$smd")
        done < <(find "$cc_mp" -name "SKILL.md" -type f 2>/dev/null)
    fi
    # Plugin skills
    local sess_dir
    for sess_dir in "${SESSION_DIRS[@]}"; do
        local remote_dir="$sess_dir/remote_cowork_plugins"
        if [[ -d "$remote_dir" ]]; then
            local pdir
            for pdir in "$remote_dir"/*/; do
                [[ -d "$pdir" && "$(basename "$pdir")" != "manifest.json" ]] || continue
                local pj_path="$pdir/.claude-plugin/plugin.json"
                local plugin_name=""
                local pjd; pjd=$(safe_read_json "$pj_path") || true
                [[ -z "$JSON_ERROR" && -n "$pjd" ]] && plugin_name=$(printf '%s' "$pjd" | jq -r '.name // ""')
                [[ -z "$plugin_name" ]] && plugin_name=$(basename "$pdir")
                local sk_dir="$pdir/skills"
                [[ -d "$sk_dir" ]] || continue
                local sd
                for sd in "$sk_dir"/*/; do
                    [[ -d "$sd" ]] || continue
                    local smd="$sd/SKILL.md"
                    [[ -f "$smd" ]] || continue
                    parse_skill_frontmatter "$smd"
                    SK_NAMES+=("${SKILL_FM_NAME:-$(basename "$sd")}"); SK_DESCS+=("$SKILL_FM_DESC")
                    SK_SRCS+=("plugin"); SK_PLUGINS+=("$plugin_name"); SK_PATHS+=("$smd")
                done
            done
        fi
        # Cached plugin skills
        local cache_base="$sess_dir/cowork_plugins/cache"
        if [[ -d "$cache_base" ]]; then
            local mp_dir
            for mp_dir in "$cache_base"/*/; do
                [[ -d "$mp_dir" ]] || continue
                local cpd
                for cpd in "$mp_dir"*/; do
                    [[ -d "$cpd" ]] || continue
                    local latest; latest=$(ls -1d "$cpd"*/ 2>/dev/null | sort -t. -k1,1rn -k2,2rn -k3,3rn | head -1)
                    [[ -n "$latest" ]] || continue
                    local pj_path="$latest/.claude-plugin/plugin.json"
                    local plugin_name=""
                    local pjd; pjd=$(safe_read_json "$pj_path") || true
                    [[ -z "$JSON_ERROR" && -n "$pjd" ]] && plugin_name=$(printf '%s' "$pjd" | jq -r '.name // ""')
                    [[ -z "$plugin_name" ]] && plugin_name=$(basename "$cpd")
                    local sk_dir="$latest/skills"
                    [[ -d "$sk_dir" ]] || continue
                    local sd
                    for sd in "$sk_dir"/*/; do
                        [[ -d "$sd" ]] || continue
                        local smd="$sd/SKILL.md"
                        [[ -f "$smd" ]] || continue
                        parse_skill_frontmatter "$smd"
                        SK_NAMES+=("${SKILL_FM_NAME:-$(basename "$sd")}"); SK_DESCS+=("$SKILL_FM_DESC")
                        SK_SRCS+=("plugin"); SK_PLUGINS+=("$plugin_name"); SK_PATHS+=("$smd")
                    done
                done
            done
        fi
        # Session-local user skills: local_<session>/.claude/skills/<skill>/SKILL.md
        local local_sess
        for local_sess in "$sess_dir"/local_*/; do
            [[ -d "$local_sess" ]] || continue
            local ls_skills="$local_sess/.claude/skills"
            [[ -d "$ls_skills" ]] || continue
            local ls_dir
            for ls_dir in "$ls_skills"/*/; do
                [[ -d "$ls_dir" ]] || continue
                local smd="$ls_dir/SKILL.md"
                [[ -f "$smd" ]] || continue
                parse_skill_frontmatter "$smd"
                local sn="${SKILL_FM_NAME:-$(basename "$ls_dir")}"
                local dup=false; local si
                for ((si=0; si<${#SK_NAMES[@]}; si++)); do [[ "${SK_NAMES[$si]}" == "$sn" ]] && dup=true && break; done
                [[ "$dup" == "true" ]] && continue
                SK_NAMES+=("$sn"); SK_DESCS+=("$SKILL_FM_DESC"); SK_SRCS+=("user"); SK_PLUGINS+=(""); SK_PATHS+=("$smd")
            done
        done
    done
}

collect_scheduled_tasks() { # uses SESSION_DIRS
    local sess_dir
    for sess_dir in "${SESSION_DIRS[@]}"; do
        local tf="$sess_dir/scheduled-tasks.json"
        local data
        data=$(safe_read_json "$tf") || true
        [[ -n "$JSON_ERROR" || -z "$data" || "$data" == "null" ]] && continue

        local tasks_json
        local dtype; dtype=$(printf '%s' "$data" | jq -r 'type')
        if [[ "$dtype" == "array" ]]; then tasks_json="$data"
        else tasks_json=$(printf '%s' "$data" | jq -c '.scheduledTasks // .tasks // [.]'); fi
        local ttype; ttype=$(printf '%s' "$tasks_json" | jq -r 'type')
        [[ "$ttype" != "array" ]] && tasks_json="[$tasks_json]"

        local tcount; tcount=$(printf '%s' "$tasks_json" | jq 'length')
        local ti
        for ((ti=0; ti<tcount; ti++)); do
            local td; td=$(printf '%s' "$tasks_json" | jq -c ".[$ti]")
            [[ "$(printf '%s' "$td" | jq -r 'type')" != "object" ]] && continue
            local tid tcron tenabled tfpath tcreated
            tid=$(printf '%s' "$td" | jq -r '.id // .taskId // "unknown"')
            tcron=$(printf '%s' "$td" | jq -r '.cronExpression // .cron // ""')
            tenabled=$(printf '%s' "$td" | jq -r '.enabled // true')
            tfpath=$(printf '%s' "$td" | jq -r '.filePath // .skillPath // ""')
            tcreated=$(printf '%s' "$td" | jq -r '.createdAt // ""')
            local tcron_eng=""; [[ -n "$tcron" ]] && tcron_eng=$(cron_to_english "$tcron")
            local tsname="" tsdesc="" tprompt=""
            if [[ -n "$tfpath" && -f "$tfpath" ]]; then
                local stext
                stext=$(safe_read_text "$tfpath") || true
                if [[ -z "$JSON_ERROR" && -n "$stext" ]]; then
                    parse_skill_frontmatter "$tfpath"
                    tsname="$SKILL_FM_NAME"; tsdesc="$SKILL_FM_DESC"
                    local body
                    body=$(printf '%s' "$stext" | sed -n '/^---/{n; :a; /^---/!{N; ba}; N; p;}' | head -20)
                    [[ -z "$body" ]] && body="$stext"
                    tprompt="${body:0:200}"
                fi
            elif [[ -n "$tfpath" ]]; then
                tsname="[SKILL FILE MISSING]"
            fi
            ST_IDS+=("$tid"); ST_CRONS+=("$tcron"); ST_CRON_ENG+=("$tcron_eng")
            ST_ENABLEDS+=("$tenabled"); ST_FPATHS+=("$tfpath"); ST_CREATED+=("$tcreated")
            ST_SNAMES+=("$tsname"); ST_SDESCS+=("$tsdesc"); ST_PROMPTS+=("$tprompt")
            [[ "$tenabled" == "true" ]] && add_finding "WARN" "Scheduled Tasks" "Active scheduled task: ${tsname:-$tid}" "Cron: $tcron ($tcron_eng)"
        done
    done
}

collect_blocklist() { # claude_dir
    local claude_dir="$1"
    local bl_path="$claude_dir/extensions-blocklist.json"
    local data
    data=$(safe_read_json "$bl_path") || true
    if [[ -n "$JSON_ERROR" ]]; then BLOCKLIST_STATUS="$JSON_ERROR"; return; fi
    [[ -z "$data" || "$data" == "null" ]] && { BLOCKLIST_STATUS="ABSENT"; return; }

    local total=0
    local dtype; dtype=$(printf '%s' "$data" | jq -r 'type')
    if [[ "$dtype" == "array" ]]; then
        total=$(printf '%s' "$data" | jq '[.[] | if type == "object" then (.entries // []) | length else 1 end] | add // 0')
    elif [[ "$dtype" == "object" ]]; then
        local entries_json
        entries_json=$(printf '%s' "$data" | jq -c '.blocklist // .extensions // []')
        local etype; etype=$(printf '%s' "$entries_json" | jq -r 'type')
        if [[ "$etype" == "array" ]]; then
            total=$(printf '%s' "$entries_json" | jq '[.[] | if type == "object" then (.entries // []) | length else 1 end] | add // 0')
        elif [[ "$etype" == "object" ]]; then
            total=$(printf '%s' "$entries_json" | jq 'length')
        fi
    fi
    BLOCKLIST_ENTRIES=$total
    if ((total == 0)); then
        add_finding "WARN" "Security" "Extension blocklist is empty — no governance controls"
        BLOCKLIST_STATUS="EMPTY"
    else
        BLOCKLIST_STATUS="$total entries"
    fi
    get_file_permission "$bl_path"
}

collect_claude_code_settings() { # home
    local home="$1"
    local settings_path="$home/$CLAUDE_CODE_DIR/settings.json"
    local data
    data=$(safe_read_json "$settings_path") || true
    [[ -n "$JSON_ERROR" || -z "$data" || "$data" == "null" ]] && return
    CLAUDE_CODE_JSON="$data"
    local allow
    allow=$(printf '%s' "$data" | jq -r '.permissions.allow // [] | join(", ")' 2>/dev/null) || true
    [[ -n "$allow" ]] && add_finding "INFO" "Claude Code" "Permissions granted: $allow"
    get_file_permission "$settings_path"
}

collect_file_permissions() { # claude_dir home
    local claude_dir="$1" home="$2"
    local extra_paths=(
        "$claude_dir/claude_desktop_config.json"
        "$claude_dir/config.json"
        "$claude_dir/extensions-installations.json"
        "$claude_dir/extensions-blocklist.json"
        "$home/$CLAUDE_CODE_DIR/settings.json"
    )
    local -A existing
    local i; for ((i=0; i<${#FP_PATHS[@]}; i++)); do existing["${FP_PATHS[$i]}"]=1; done
    for p in "${extra_paths[@]}"; do
        [[ -z "${existing[$p]:-}" ]] && get_file_permission "$p"
    done
    for ((i=0; i<${#FP_PATHS[@]}; i++)); do
        if [[ "${FP_STATS[$i]}" != "OK" ]]; then
            local sev="WARN"; [[ "${FP_STATS[$i]}" == CRITICAL* ]] && sev="CRITICAL"
            local short; short=$(basename "${FP_PATHS[$i]}")
            add_finding "$sev" "File Permissions" "Insecure permissions on $short: ${FP_STATS[$i]}" "Mode: ${FP_MODES[$i]}, Path: ${FP_PATHS[$i]}"
        fi
    done
}

collect_runtime() { # claude_dir home
    local claude_dir="$1" home="$2"
    local stdout
    stdout=$(pgrep -fl Claude 2>/dev/null) || true
    if [[ -n "$stdout" ]]; then
        local pcount; pcount=$(echo "$stdout" | wc -l | tr -d ' ')
        RUNTIME_INFO[claude_processes]="$stdout"
        add_finding "INFO" "Runtime" "Claude is running ($pcount processes)"
    fi

    stdout=$(pmset -g assertions 2>/dev/null) || true
    if [[ -n "$stdout" ]]; then
        RUNTIME_INFO[pmset_assertions]="$stdout"
        while IFS= read -r line; do
            local lower="${(L)line}"
            if [[ "$lower" == *claude* || "$lower" == *electron* ]]; then
                add_finding "WARN" "Runtime" "Sleep prevention assertion by Claude/Electron" "${line## }"
            fi
        done <<< "$stdout"
    fi

    if [[ "$(id -u)" == "0" && -n "$AUDIT_USER" ]]; then
        stdout=$(crontab -l -u "$AUDIT_USER" 2>/dev/null) || true
    else
        stdout=$(crontab -l 2>/dev/null) || true
    fi
    if [[ -n "$stdout" ]]; then
        RUNTIME_INFO[crontab]="$stdout"
        while IFS= read -r line; do
            [[ "${(L)line}" == *claude* ]] && add_finding "WARN" "Runtime" "Claude-related crontab entry found" "${line## }"
        done <<< "$stdout"
    fi

    local la_dir="$home/Library/LaunchAgents"
    local claude_plists=""
    if [[ -d "$la_dir" ]]; then
        local plist
        for plist in "$la_dir"/*; do
            [[ -f "$plist" ]] || continue
            local bn; bn=$(basename "$plist")
            [[ "${(L)bn}" == *claude* ]] && { [[ -n "$claude_plists" ]] && claude_plists+=", "; claude_plists+="$bn"; }
        done
    fi
    RUNTIME_INFO[launch_agents]="$claude_plists"
    [[ -n "$claude_plists" ]] && add_finding "WARN" "Runtime" "Claude LaunchAgent(s) found: $claude_plists"

    local debug_dir="$claude_dir/debug"
    if [[ -d "$debug_dir" ]]; then
        local size_kb
        size_kb=$(du -sk "$debug_dir" 2>/dev/null | awk '{print $1}')
        local size_b=$((size_kb * 1024))
        RUNTIME_INFO[debug_dir_size]=$(fmt_bytes "$size_b")
        ((size_b > 104857600)) && add_finding "WARN" "Runtime" "Debug directory is large: $(fmt_bytes "$size_b")" "$debug_dir"
    fi
}

collect_cookies() { # claude_dir
    local claude_dir="$1"
    local label _path
    for label in Cookies Cookies-journal; do
        _path="$claude_dir/$label"
        [[ -e "$_path" ]] || continue
        get_file_permission "$_path"
        local idx=$(( ${#FP_PATHS[@]} - 1 ))
        COOKIES_INFO["${label}_present"]="true"
        COOKIES_INFO["${label}_mode"]="${FP_MODES[$idx]}"
        COOKIES_INFO["${label}_status"]="${FP_STATS[$idx]}"
    done
}

# ── Recommendations ──────────────────────────────────────────────────────────
RECOMMENDATIONS=()
build_recommendations() {
    RECOMMENDATIONS=(); local i
    [[ "${DESKTOP_PREFS[keepAwakeEnabled]:-false}" == "true" ]] && \
        RECOMMENDATIONS+=("Keep Awake is ON — prevents macOS sleep")

    local active_count=0
    for ((i=0; i<${#ST_ENABLEDS[@]}; i++)); do [[ "${ST_ENABLEDS[$i]}" == "true" ]] && ((active_count++)); done
    ((active_count > 0)) && RECOMMENDATIONS+=("$active_count active scheduled task(s) — review purpose and prompts")

    local unsigned_names=""
    for ((i=0; i<${#EXT_SIGNEDS[@]}; i++)); do
        [[ "${EXT_SIGNEDS[$i]}" == "false" ]] && { [[ -n "$unsigned_names" ]] && unsigned_names+=", "; unsigned_names+="${EXT_NAMES[$i]}"; }
    done
    [[ -n "$unsigned_names" ]] && RECOMMENDATIONS+=("Unsigned extensions: $unsigned_names")

    for ((i=0; i<${#EXT_DANGER_STR[@]}; i++)); do
        [[ -n "${EXT_DANGER_STR[$i]}" ]] && RECOMMENDATIONS+=("Extension '${EXT_NAMES[$i]}' has dangerous tools: ${EXT_DANGER_STR[$i]//,/, }")
    done

    ((${#MCP_NAMES[@]} > 0)) && RECOMMENDATIONS+=("${#MCP_NAMES[@]} MCP server(s) configured — verify each is expected")

    local has_oauth=false
    for ((i=0; i<${#FINDING_MSG[@]}; i++)); do
        [[ "${FINDING_SECT[$i]}" == "Security" && "${FINDING_SEV[$i]}" == "WARN" && "${(L)FINDING_MSG[$i]}" == *oauth* ]] && has_oauth=true
    done
    [[ "$has_oauth" == "true" ]] && RECOMMENDATIONS+=("OAuth token stored in plaintext config.json")

    local al_count=0
    for ((i=0; i<${#FINDING_MSG[@]}; i++)); do [[ "${(L)FINDING_MSG[$i]}" == *"allowlist disabled"* ]] && ((al_count++)); done
    ((al_count > 0)) && RECOMMENDATIONS+=("Extension allowlist disabled ($al_count org scope(s))")

    local perm_count=0
    for ((i=0; i<${#FP_STATS[@]}; i++)); do [[ "${FP_STATS[$i]}" != "OK" ]] && ((perm_count++)); done
    ((perm_count > 0)) && RECOMMENDATIONS+=("$perm_count config file(s) with overly permissive permissions — chmod 600")

    [[ "${COWORK_PREFS[coworkWebSearchEnabled]:-false}" == "true" ]] && \
        RECOMMENDATIONS+=("Cowork web search enabled — autonomous internet access")

    local remote_names=""
    for ((i=0; i<${#PLG_SRCS[@]}; i++)); do
        [[ "${PLG_SRCS[$i]}" == "remote" ]] && { [[ -n "$remote_names" ]] && remote_names+=", "; remote_names+="${PLG_NAMES[$i]}"; }
    done
    [[ -n "$remote_names" ]] && RECOMMENDATIONS+=("Remote plugins: $remote_names")

    local cached_names=""
    for ((i=0; i<${#PLG_SRCS[@]}; i++)); do
        [[ "${PLG_SRCS[$i]}" == "cached" ]] && { [[ -n "$cached_names" ]] && cached_names+=", "; cached_names+="${PLG_NAMES[$i]}"; }
    done
    [[ -n "$cached_names" ]] && RECOMMENDATIONS+=("Cached (not installed) plugins: $cached_names")

    local web_conn_names="" wcc=0
    for ((i=0; i<${#CONN_CATS[@]}; i++)); do
        [[ "${CONN_CATS[$i]}" == "web" ]] && { ((wcc++)); [[ -n "$web_conn_names" ]] && web_conn_names+=", "; web_conn_names+="${CONN_NAMES[$i]}"; }
    done
    ((wcc > 0)) && RECOMMENDATIONS+=("$wcc web connector(s) authenticated: $web_conn_names")
}

# ── ASCII Renderer ────────────────────────────────────────────────────────────
USE_COLOR=false
[[ -t 1 ]] && USE_COLOR=true

_c() { $USE_COLOR && printf '\033[%sm%s\033[0m' "$1" "$2" || printf '%s' "$2"; }
_red()    { _c "1;31" "$1"; }
_yellow() { _c "33" "$1"; }
_cyan()   { _c "36" "$1"; }
_green()  { _c "32" "$1"; }
_bold()   { _c "1" "$1"; }
_dim()    { _c "2" "$1"; }
_sev_color() {
    local s="$1" t="${2:-$1}"
    case "$s" in CRITICAL) _red "$t";; WARN|REVIEW) _yellow "$t";; INFO) _cyan "$t";; OK|PASS) _green "$t";; *) printf '%s' "$t";; esac
}
_on_off() {
    case "$1" in true) _yellow "ON";; false) _green "OFF";; "") _dim "-";; *) printf '%s' "$1";; esac
}

_strip_ansi() { sed $'s/\033\\[[0-9;]*m//g' <<< "$1"; }

_section_hdr() {
    local title="$1" w="${2:-66}"
    local prefix; prefix=$(printf '%s %s ' "────" "$title")
    local plen=${#prefix} remaining=$((w - plen))
    ((remaining < 0)) && remaining=0
    printf '%s' "$prefix"; printf '─%.0s' $(seq 1 $remaining); printf '\n'
}

ascii_table() { # "H1|H2" "row1col1|row1col2\nrow2..." "w1|w2"
    local -a headers widths
    IFS='|' read -rA headers <<< "$1"
    IFS='|' read -rA widths <<< "$3"
    local ncols=${#headers[@]} i
    # Top
    local top="┌"; for ((i=0; i<ncols; i++)); do
        local seg; seg=$(printf '─%.0s' $(seq 1 $((widths[i]+2)))); top+="$seg"; ((i<ncols-1)) && top+="┬"
    done; echo "${top}┐"
    # Header
    local hdr="│"; for ((i=0; i<ncols; i++)); do
        local h="${headers[$i]}" w=${widths[$i]}; local p="${h:0:$w}"
        local pad=$((w-${#p})); ((pad<0)) && pad=0; local sp; sp=$(printf '%*s' "$pad" "")
        hdr+=" ${p}${sp} │"
    done; echo "$hdr"
    # Sep
    local sep="├"; for ((i=0; i<ncols; i++)); do
        local seg; seg=$(printf '─%.0s' $(seq 1 $((widths[i]+2)))); sep+="$seg"; ((i<ncols-1)) && sep+="┼"
    done; echo "${sep}┤"
    # Rows
    while IFS= read -r row_line; do
        [[ -z "$row_line" ]] && continue
        IFS='|' read -rA cells <<< "$row_line"
        local rline="│"; for ((i=0; i<ncols; i++)); do
            local val="${cells[$i]:-}" w=${widths[$i]}
            local plain; plain=$(_strip_ansi "$val"); plain="${plain:0:$w}"
            local pad=$((w-${#plain})); ((pad<0)) && pad=0; local sp; sp=$(printf '%*s' "$pad" "")
            rline+=" ${plain}${sp} │"
        done; echo "$rline"
    done <<< "$2"
    # Bottom
    local bot="└"; for ((i=0; i<ncols; i++)); do
        local seg; seg=$(printf '─%.0s' $(seq 1 $((widths[i]+2)))); bot+="$seg"; ((i<ncols-1)) && bot+="┴"
    done; echo "${bot}┘"
}

render_ascii() {
    local quiet="${1:-false}" i w=66
    local o='\033[38;5;208m' g='\033[38;5;243m' r='\033[0m'
    printf "${o}"
    cat <<'BANNER'
  ██████ ██       █████  ██    ██ ██████  ██ ████████       ███████ ███████  ██████
 ██      ██      ██   ██ ██    ██ ██   ██ ██    ██          ██      ██      ██
 ██      ██      ███████ ██    ██ ██   ██ ██    ██    █████ ███████ █████   ██
 ██      ██      ██   ██ ██    ██ ██   ██ ██    ██               ██ ██      ██
  ██████ ███████ ██   ██  ██████  ██████  ██    ██          ███████ ███████  ██████
BANNER
    printf "${g}  // Claude security auditing CLI — skills, plugins & misconfiguration detection${r}\n\n"
    printf '╔'; printf '═%.0s' $(seq 1 $w); printf '╗\n'
    printf '║%*s%s%*s║\n' $(( (w-${#TIMESTAMP})/2 )) '' "$TIMESTAMP" $(( (w-${#TIMESTAMP}+1)/2 )) ''
    local info="Host: $HOSTNAME_VAL | User: $AUDIT_USER"
    printf '║%*s%s%*s║\n' $(( (w-${#info})/2 )) '' "$info" $(( (w-${#info}+1)/2 )) ''
    printf '╚'; printf '═%.0s' $(seq 1 $w); printf '╝\n\n'

    _section_hdr "SUMMARY"
    local n_inst=0 n_rem=0 n_cach=0 n_web=0 n_nc=0 warn_c=0 rev_c=0
    for ((i=0;i<${#PLG_SRCS[@]};i++)); do case "${PLG_SRCS[$i]}" in installed) ((n_inst++));; remote) ((n_rem++));; cached) ((n_cach++));; esac; done
    for ((i=0;i<${#CONN_CATS[@]};i++)); do case "${CONN_CATS[$i]}" in web) ((n_web++));; not_connected) ((n_nc++));; esac; done
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do [[ "${FINDING_SEV[$i]}" == "WARN" ]] && ((warn_c++)); [[ "${FINDING_SEV[$i]}" == "REVIEW" ]] && ((rev_c++)); done
    echo "  Scheduled tasks: ${#ST_IDS[@]}  |  MCP servers: ${#MCP_NAMES[@]}  |  Extensions: ${#EXT_NAMES[@]}"
    echo "  Plugins: $n_inst installed, $n_rem remote, $n_cach cached  |  Connectors: $n_web web, $n_nc not connected"
    echo "  Skills: ${#SK_NAMES[@]}  |  Findings: $warn_c warnings, $rev_c items to review"; echo

    # Desktop Settings
    local kae="${DESKTOP_PREFS[keepAwakeEnabled]:-false}"
    if [[ "$quiet" != "true" ]]; then
        _section_hdr "DESKTOP SETTINGS"
        printf '  keepAwakeEnabled:              %s' "$(_on_off "$kae")"; [[ "$kae" == "true" ]] && printf '   ⚠ Prevents macOS from sleeping'; echo
        printf '  menuBarEnabled:                %s\n' "$(_on_off "${DESKTOP_PREFS[menuBarEnabled]:-false}")"
        printf '  sidebarMode:                   %s\n' "${DESKTOP_PREFS[sidebarMode]:-$(_dim "-")}"
        printf '  quickEntryShortcut:            %s\n' "${DESKTOP_PREFS[quickEntryShortcut]:-$(_dim "-")}"; echo
    elif [[ "$kae" == "true" ]]; then
        _section_hdr "DESKTOP SETTINGS"
        printf '  keepAwakeEnabled:              %s   ⚠ Prevents macOS from sleeping\n' "$(_on_off "$kae")"; echo
    fi

    # Cowork Settings
    local cst="${COWORK_PREFS[coworkScheduledTasksEnabled]:-false}" ccd="${COWORK_PREFS[ccdScheduledTasksEnabled]:-false}" cws="${COWORK_PREFS[coworkWebSearchEnabled]:-false}"
    if [[ "$quiet" != "true" ]]; then
        _section_hdr "COWORK SETTINGS"
        printf '  scheduledTasksEnabled:         %s' "$(_on_off "$cst")"; [[ "$cst" == "true" ]] && printf '   ⚠ Autonomous task execution'; echo
        printf '  ccdScheduledTasksEnabled:      %s' "$(_on_off "$ccd")"; [[ "$ccd" == "true" ]] && printf '   ⚠ Code Desktop scheduled tasks'; echo
        printf '  webSearchEnabled:              %s' "$(_on_off "$cws")"; [[ "$cws" == "true" ]] && printf '   ⚠ Autonomous internet access'; echo
        printf '  networkMode:                   %s\n' "${COWORK_NETWORK_MODE:-$(_dim "-")}"
        ((${#COWORK_ENABLED_PLUGINS[@]}>0)) && printf '  Enabled plugins:               %s\n' "$(IFS=', '; echo "${COWORK_ENABLED_PLUGINS[*]}")"
        for mk in "${(k)COWORK_MARKETPLACES_JSON[@]}"; do
            local st sr; st=$(printf '%s' "${COWORK_MARKETPLACES_JSON[$mk]}" | jq -r '.source.source // "?"' 2>/dev/null)
            sr=$(printf '%s' "${COWORK_MARKETPLACES_JSON[$mk]}" | jq -r '.source.repo // .source.path // ""' 2>/dev/null)
            printf '  Marketplace source:            %s (%s: %s)\n' "$mk" "$st" "$sr"
        done; echo
    else
        local wi=()
        [[ "$cst" == "true" ]] && wi+=("$(printf '  scheduledTasksEnabled:         %s   ⚠ Autonomous task execution' "$(_on_off "$cst")")")
        [[ "$ccd" == "true" ]] && wi+=("$(printf '  ccdScheduledTasksEnabled:      %s   ⚠ Code Desktop scheduled tasks' "$(_on_off "$ccd")")")
        [[ "$cws" == "true" ]] && wi+=("$(printf '  webSearchEnabled:              %s   ⚠ Autonomous internet access' "$(_on_off "$cws")")")
        if ((${#wi[@]}>0)); then _section_hdr "COWORK SETTINGS"; for w in "${wi[@]}"; do echo "$w"; done; echo; fi
    fi

    # MCP Servers
    if [[ "$quiet" != "true" || ${#MCP_NAMES[@]} -gt 0 ]]; then
        _section_hdr "MCP SERVERS"
        if ((${#MCP_NAMES[@]}>0)); then
            local rows=""
            for ((i=0;i<${#MCP_NAMES[@]};i++)); do
                [[ -n "$rows" ]] && rows+=$'\n'
                rows+="$(truncate_str "${MCP_NAMES[$i]}" 26)|$(truncate_str "${MCP_CMDS[$i]}" 30)|$(truncate_str "${MCP_ARGS_STR[$i]}" 16)|$(truncate_str "${MCP_ENV_KEYS[$i]}" 16)"
            done
            ascii_table "Server Name|Command|Args|Env Vars" "$rows" "26|30|16|16"
            echo "  $(_yellow '[REVIEW]') MCP servers can execute arbitrary commands and access external services."
        else echo "  $(_green 'No MCP servers configured.')"; fi; echo
    fi

    # Plugins
    local has_plg=false; ((n_inst>0||n_rem>0||n_cach>0)) && has_plg=true
    if [[ "$quiet" != "true" || "$has_plg" == "true" ]]; then
        _section_hdr "PLUGINS"
        if ((n_inst>0)); then
            echo "  $(_bold 'Installed:')"; local rows=""
            for ((i=0;i<${#PLG_SRCS[@]};i++)); do [[ "${PLG_SRCS[$i]}" != "installed" ]] && continue
                [[ -n "$rows" ]] && rows+=$'\n'
                rows+="$(truncate_str "${PLG_NAMES[$i]}" 24)|$(truncate_str "${PLG_VERS[$i]}" 8)|$(truncate_str "${PLG_MPS[$i]}" 24)|$(truncate_str "${PLG_SCOPES[$i]}" 6)|$(truncate_str "${PLG_INSTALLED_ATS[$i]:0:10}" 24)"
            done; ascii_table "Name|Version|Source|Scope|Installed" "$rows" "24|8|24|6|24"
        fi
        if ((n_rem>0)); then
            echo "  $(_bold 'Remote (org-deployed):')"; local rows=""
            for ((i=0;i<${#PLG_SRCS[@]};i++)); do [[ "${PLG_SRCS[$i]}" != "remote" ]] && continue
                [[ -n "$rows" ]] && rows+=$'\n'
                rows+="$(truncate_str "${PLG_NAMES[$i]}" 16)|$(truncate_str "${PLG_VERS[$i]}" 8)|$(truncate_str "${PLG_AUTHORS[$i]}" 12)|$(truncate_str "${PLG_MPS[$i]}" 24)|${PLG_SKILL_COUNTS[$i]}"
            done; ascii_table "Name|Version|Author|Marketplace|Skills" "$rows" "16|8|12|24|6"
        fi
        if ((n_cach>0)); then
            echo "  $(_bold 'Cached (downloaded):')"
            for ((i=0;i<${#PLG_SRCS[@]};i++)); do [[ "${PLG_SRCS[$i]}" != "cached" ]] && continue
                echo "    ${PLG_NAMES[$i]} v${PLG_VERS[$i]} (${PLG_MPS[$i]}) — ${PLG_AUTHORS[$i]}"; done
        fi
        if [[ "$quiet" != "true" && ${#MARKETPLACE_AVAILABLE[@]} -gt 0 ]]; then
            echo "  $(_bold 'Available in marketplace:')"
            echo "    $(printf '%s\n' "${MARKETPLACE_AVAILABLE[@]}" | sort -u | tr '\n' ', ' | sed 's/,$//')"
        fi
        [[ "$has_plg" == "false" ]] && echo "  No plugins found."; echo
    fi

    # Connectors
    local web_i=() desk_i=() nc_i=()
    for ((i=0;i<${#CONN_CATS[@]};i++)); do case "${CONN_CATS[$i]}" in web) web_i+=("$i");; desktop) desk_i+=("$i");; not_connected) nc_i+=("$i");; esac; done
    if [[ "$quiet" != "true" || ${#web_i[@]} -gt 0 || ${#nc_i[@]} -gt 0 ]]; then
        _section_hdr "CONNECTORS"
        if ((${#web_i[@]}>0)); then
            echo "  $(_bold "Web") (${#web_i[@]} connected)"; local rows=""
            for idx in "${web_i[@]}"; do
                local tag=""; [[ -n "${CONN_TAGS[$idx]}" ]] && tag=" (${CONN_TAGS[$idx]})"
                [[ -n "$rows" ]] && rows+=$'\n'; rows+="$(truncate_str "${CONN_NAMES[$idx]}$tag" 30)|${CONN_TOOLS[$idx]:-"-"}"
            done; ascii_table "Connector|Tools" "$rows" "30|6"
        fi
        if ((${#desk_i[@]}>0)) && [[ "$quiet" != "true" ]]; then
            echo "  $(_bold "Desktop") (${#desk_i[@]})"
            for idx in "${desk_i[@]}"; do local tag=""; [[ -n "${CONN_TAGS[$idx]}" ]] && tag="  $(_dim "${CONN_TAGS[$idx]}")"; echo "    ${CONN_NAMES[$idx]}$tag"; done
        fi
        if ((${#nc_i[@]}>0)); then
            echo "  $(_bold "Not connected") (${#nc_i[@]})"; for idx in "${nc_i[@]}"; do echo "    ${CONN_NAMES[$idx]}"; done
        fi
        ((${#web_i[@]}==0 && ${#nc_i[@]}==0)) && echo "  No connectors found."; echo
    fi

    # Skills
    local usk_i=() psk_i=()
    for ((i=0;i<${#SK_SRCS[@]};i++)); do case "${SK_SRCS[$i]}" in user) usk_i+=("$i");; plugin) psk_i+=("$i");; esac; done
    if [[ "$quiet" != "true" || ${#usk_i[@]} -gt 0 || ${#psk_i[@]} -gt 0 ]]; then
        _section_hdr "SKILLS"
        if ((${#usk_i[@]}>0)); then
            echo "  $(_bold 'User-created:')"; local rows=""
            for idx in "${usk_i[@]}"; do [[ -n "$rows" ]] && rows+=$'\n'
                rows+="$(truncate_str "${SK_NAMES[$idx]}" 20)|$(truncate_str "${SK_DESCS[$idx]}" 30)|$(truncate_str "${SK_PATHS[$idx]}" 40)"
            done; ascii_table "Name|Description|Path" "$rows" "20|30|40"
        fi
        if ((${#psk_i[@]}>0)) && [[ "$quiet" != "true" ]]; then
            echo "  $(_bold 'Plugin skills:')"; local prows=""
            for idx in "${psk_i[@]}"; do [[ -n "$prows" ]] && prows+=$'\n'
                prows+="$(truncate_str "${SK_NAMES[$idx]}" 24)|$(truncate_str "${SK_PLUGINS[$idx]:-unknown}" 22)|$(truncate_str "${SK_DESCS[$idx]}" 40)"
            done; ascii_table "Skill|Plugin|Description" "$prows" "24|22|40"
        elif ((${#psk_i[@]}>0)); then
            local -A pns; for idx in "${psk_i[@]}"; do pns["${SK_PLUGINS[$idx]:-unknown}"]=1; done
            echo "  Plugin skills: ${#psk_i[@]} across $(IFS=', '; echo "${(k)pns[*]}")"
        fi
        ((${#usk_i[@]}==0 && ${#psk_i[@]}==0)) && echo "  No skills found."; echo
    fi

    # Scheduled Tasks
    local act_i=(); for ((i=0;i<${#ST_ENABLEDS[@]};i++)); do [[ "${ST_ENABLEDS[$i]}" == "true" ]] && act_i+=("$i"); done
    if [[ "$quiet" != "true" || ${#act_i[@]} -gt 0 ]]; then
        _section_hdr "SCHEDULED TASKS"
        local show_i=()
        [[ "$quiet" == "true" ]] && show_i=("${act_i[@]+"${act_i[@]}"}") || { for ((i=0;i<${#ST_IDS[@]};i++)); do show_i+=("$i"); done; }
        if ((${#show_i[@]}>0)); then
            local rows=""
            for idx in "${show_i[@]}"; do
                local desc="${ST_SNAMES[$idx]:-${ST_SDESCS[$idx]:-$(truncate_str "${ST_PROMPTS[$idx]}" 28)}}"
                local en="No"; [[ "${ST_ENABLEDS[$idx]}" == "true" ]] && en="Yes"
                [[ -n "$rows" ]] && rows+=$'\n'
                rows+="$(truncate_str "${ST_IDS[$idx]}" 20)|$(truncate_str "${ST_CRONS[$idx]}" 12)|$(truncate_str "${ST_CRON_ENG[$idx]}" 22)|$en|$(truncate_str "$desc" 28)"
            done; ascii_table "Task ID|Cron|Schedule|Enabled|Description" "$rows" "20|12|22|7|28"
            for idx in "${show_i[@]}"; do [[ -n "${ST_FPATHS[$idx]}" ]] && echo "    Skill: $(_dim "${ST_FPATHS[$idx]}")"; done
        else echo "  No scheduled tasks found."; fi; echo
    fi

    # Extensions
    if [[ "$quiet" != "true" || ${#EXT_NAMES[@]} -gt 0 ]]; then
        _section_hdr "EXTENSIONS (DXT)"
        if ((${#EXT_NAMES[@]}>0)); then
            local show_e=()
            if [[ "$quiet" == "true" ]]; then
                for ((i=0;i<${#EXT_SIGNEDS[@]};i++)); do [[ "${EXT_SIGNEDS[$i]}" == "false" || -n "${EXT_DANGER_STR[$i]}" ]] && show_e+=("$i"); done
            else for ((i=0;i<${#EXT_NAMES[@]};i++)); do show_e+=("$i"); done; fi
            if ((${#show_e[@]}>0)); then
                local rows=""
                for idx in "${show_e[@]}"; do
                    local stxt; [[ "${EXT_SIGNEDS[$idx]}" == "true" ]] && stxt="Yes" || stxt="No"
                    local dng="${EXT_DANGER_STR[$idx]:-"-"}"; dng="${dng//,/, }"
                    [[ -n "$rows" ]] && rows+=$'\n'
                    rows+="$(truncate_str "${EXT_NAMES[$idx]}" 20)|$(truncate_str "${EXT_VERS[$idx]}" 8)|$(truncate_str "${EXT_AUTHORS[$idx]}" 12)|$stxt|$dng"
                done; ascii_table "Name|Version|Author|Signed|Dangerous Tools" "$rows" "20|8|12|8|28"
            fi
            for name in "${(k)EXT_SETTINGS_JSON[@]}"; do
                local allowed; allowed=$(printf '%s' "${EXT_SETTINGS_JSON[$name]}" | jq -r '.userConfig.allowed_directories // .userConfig.allowedDirectories // [] | join(", ")' 2>/dev/null)
                [[ -n "$allowed" ]] && echo "  Filesystem allowed directories: $allowed"
            done
        else echo "  No DXT extensions installed."; fi; echo
    fi

    # Security Findings
    _section_hdr "SECURITY FINDINGS"; local found_sec=false
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        [[ "${FINDING_SECT[$i]}" == "Security" && ("${(L)FINDING_MSG[$i]}" == *oauth* || "${(L)FINDING_MSG[$i]}" == *token*) ]] && {
            echo "  $(_sev_color "${FINDING_SEV[$i]}" "[${FINDING_SEV[$i]}]") ${FINDING_MSG[$i]}"; found_sec=true; }
    done
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        [[ "${FINDING_SECT[$i]}" == "Security" && "${(L)FINDING_MSG[$i]}" == *allowlist* ]] && {
            echo "  $(_sev_color "${FINDING_SEV[$i]}" "[${FINDING_SEV[$i]}]") ${FINDING_MSG[$i]}"; found_sec=true; }
    done
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        [[ "${FINDING_SECT[$i]}" == "Security" && "${(L)FINDING_MSG[$i]}" == *blocklist* ]] && {
            echo "  $(_sev_color "${FINDING_SEV[$i]}" "[${FINDING_SEV[$i]}]") ${FINDING_MSG[$i]}"; found_sec=true; }
    done
    local perm_iss=false; local -A pseen
    for ((i=0;i<${#FP_STATS[@]};i++)); do
        [[ "${FP_STATS[$i]}" != "OK" && -z "${pseen[${FP_PATHS[$i]}]:-}" ]] || continue
        [[ "$perm_iss" == "true" ]] || { echo "  $(_yellow 'File permission issues:')"; perm_iss=true; found_sec=true; }
        pseen["${FP_PATHS[$i]}"]=1; echo "    $(basename "${FP_PATHS[$i]}") (${FP_MODES[$i]}): ${FP_STATS[$i]}"
    done
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        [[ "${FINDING_SECT[$i]}" == "Runtime" && "${FINDING_SEV[$i]}" != "INFO" && "${FINDING_SEV[$i]}" != "OK" ]] && {
            echo "  $(_sev_color "${FINDING_SEV[$i]}" "[${FINDING_SEV[$i]}]") ${FINDING_MSG[$i]}"; found_sec=true; }
    done
    [[ "$found_sec" == "true" ]] || echo "  $(_green 'No security issues detected.')"; echo

    _section_hdr "RECOMMENDATIONS"
    if ((${#RECOMMENDATIONS[@]}>0)); then
        for ((i=0;i<${#RECOMMENDATIONS[@]};i++)); do echo "  $((i+1)). ${RECOMMENDATIONS[$i]}"; done
    else echo "  $(_green 'No issues requiring action.')"; fi; echo
    _dim "CLAUDIT v${VERSION} — read-only audit, no files modified."; echo
}

# ── HTML Renderer ─────────────────────────────────────────────────────────────
_h() { html_escape "$1"; }
_badge_html() {
    local color; case "$1" in CRITICAL) color="#dc3545";; WARN) color="#ffc107";; INFO) color="#17a2b8";;
        OK|PASS) color="#28a745";; REVIEW) color="#fd7e14";; *) color="#6c757d";; esac
    printf '<span class="badge" style="background:%s;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.85em;">%s</span>' "$color" "$(_h "$1")"
}
_on_off_html() {
    case "$1" in true) echo '<span style="color:#ffc107;font-weight:600">ON</span>';; false) echo '<span style="color:#28a745">OFF</span>';;
        "") echo '<span style="color:#666">-</span>';; *) _h "$1";; esac
}

render_html() {
    local quiet="${1:-false}" i
    local n_inst=0 n_rem=0 n_cach=0 n_web=0 n_nc=0 warn_c=0 rev_c=0
    for ((i=0;i<${#PLG_SRCS[@]};i++)); do case "${PLG_SRCS[$i]}" in installed) ((n_inst++));; remote) ((n_rem++));; cached) ((n_cach++));; esac; done
    for ((i=0;i<${#CONN_CATS[@]};i++)); do [[ "${CONN_CATS[$i]}" == "web" ]] && ((n_web++)); [[ "${CONN_CATS[$i]}" == "not_connected" ]] && ((n_nc++)); done
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do [[ "${FINDING_SEV[$i]}" == "WARN" ]] && ((warn_c++)); [[ "${FINDING_SEV[$i]}" == "REVIEW" ]] && ((rev_c++)); done

    cat <<HTMLEOF
<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="CLAUDIT v${VERSION}"><title>CLAUDIT Report — $(_h "$HOSTNAME_VAL") — $(_h "$TIMESTAMP")</title>
<style>
:root{--bg:#1a1a2e;--fg:#e0e0e0;--card:#16213e;--border:#0f3460;--accent:#e94560}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Mono',Menlo,monospace;background:var(--bg);color:var(--fg);padding:20px;line-height:1.6}
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
<p class="meta">$(_h "$TIMESTAMP") &bull; Host: $(_h "$HOSTNAME_VAL") &bull; User: $(_h "$AUDIT_USER")</p>
<div class="risk-box">
<div>Scheduled tasks: <strong>${#ST_IDS[@]}</strong> &bull; MCP servers: <strong>${#MCP_NAMES[@]}</strong> &bull; Extensions: <strong>${#EXT_NAMES[@]}</strong></div>
<div>Plugins: <strong>${n_inst}</strong> installed, <strong>${n_rem}</strong> remote, <strong>${n_cach}</strong> cached &bull; Connectors: <strong>${n_web}</strong> web, <strong>${n_nc}</strong> not connected &bull; Skills: <strong>${#SK_NAMES[@]}</strong></div>
<div style="margin-top:5px;">$(_badge_html "WARN") ${warn_c} warnings &nbsp; $(_badge_html "REVIEW") ${rev_c} items to review</div>
</div>
HTMLEOF

    # Desktop Settings
    local kae="${DESKTOP_PREFS[keepAwakeEnabled]:-false}"
    if [[ "$quiet" != "true" ]]; then
        echo '<details open><summary>Desktop Settings</summary><div class="detail-content">'
        printf '<div class="setting-row"><span class="setting-key">keepAwakeEnabled</span><span class="setting-val">%s</span>' "$(_on_off_html "$kae")"
        [[ "$kae" == "true" ]] && printf '<span class="setting-warn">&#9888; Prevents macOS from sleeping</span>'
        echo '</div>'
        printf '<div class="setting-row"><span class="setting-key">menuBarEnabled</span><span class="setting-val">%s</span></div>\n' "$(_on_off_html "${DESKTOP_PREFS[menuBarEnabled]:-false}")"
        printf '<div class="setting-row"><span class="setting-key">sidebarMode</span><span class="setting-val">%s</span></div>\n' "$(_h "${DESKTOP_PREFS[sidebarMode]:-"-"}")"
        printf '<div class="setting-row"><span class="setting-key">quickEntryShortcut</span><span class="setting-val">%s</span></div>\n' "$(_h "${DESKTOP_PREFS[quickEntryShortcut]:-"-"}")"
        echo '</div></details>'
    elif [[ "$kae" == "true" ]]; then
        printf '<details open><summary>Desktop Settings</summary><div class="detail-content"><div class="setting-row"><span class="setting-key">keepAwakeEnabled</span><span class="setting-val">%s</span><span class="setting-warn">&#9888; Prevents macOS from sleeping</span></div></div></details>\n' "$(_on_off_html true)"
    fi

    # Cowork Settings
    local cst="${COWORK_PREFS[coworkScheduledTasksEnabled]:-false}" ccd="${COWORK_PREFS[ccdScheduledTasksEnabled]:-false}" cws="${COWORK_PREFS[coworkWebSearchEnabled]:-false}"
    if [[ "$quiet" != "true" ]]; then
        echo '<details open><summary>Cowork Settings</summary><div class="detail-content">'
        for tuple in "coworkScheduledTasksEnabled|scheduledTasksEnabled|Autonomous task execution" \
                     "ccdScheduledTasksEnabled|ccdScheduledTasksEnabled|Code Desktop scheduled tasks" \
                     "coworkWebSearchEnabled|webSearchEnabled|Autonomous internet access"; do
            IFS='|' read -r key label wmsg <<< "$tuple"; local val="${COWORK_PREFS[$key]:-false}"
            printf '<div class="setting-row"><span class="setting-key">%s</span><span class="setting-val">%s</span>' "$(_h "$label")" "$(_on_off_html "$val")"
            [[ "$val" == "true" ]] && printf '<span class="setting-warn">&#9888; %s</span>' "$(_h "$wmsg")"; echo '</div>'
        done
        printf '<div class="setting-row"><span class="setting-key">networkMode</span><span class="setting-val">%s</span></div>\n' "$(_h "${COWORK_NETWORK_MODE:-"-"}")"
        ((${#COWORK_ENABLED_PLUGINS[@]}>0)) && printf '<div class="setting-row"><span class="setting-key">Enabled plugins</span><span class="setting-val">%s</span></div>\n' "$(_h "$(IFS=', '; echo "${COWORK_ENABLED_PLUGINS[*]}")")"
        echo '</div></details>'
    else
        if [[ "$cst" == "true" || "$ccd" == "true" || "$cws" == "true" ]]; then
            echo '<details open><summary>Cowork Settings</summary><div class="detail-content">'
            for tuple in "coworkScheduledTasksEnabled|scheduledTasksEnabled|Autonomous task execution" \
                         "ccdScheduledTasksEnabled|ccdScheduledTasksEnabled|Code Desktop scheduled tasks" \
                         "coworkWebSearchEnabled|webSearchEnabled|Autonomous internet access"; do
                IFS='|' read -r key label wmsg <<< "$tuple"
                [[ "${COWORK_PREFS[$key]:-false}" == "true" ]] && printf '<div class="setting-row"><span class="setting-key">%s</span><span class="setting-val">%s</span><span class="setting-warn">&#9888; %s</span></div>\n' "$(_h "$label")" "$(_on_off_html true)" "$(_h "$wmsg")"
            done; echo '</div></details>'
        fi
    fi

    # MCP Servers
    if [[ "$quiet" != "true" || ${#MCP_NAMES[@]} -gt 0 ]]; then
        echo '<details open><summary>MCP Servers</summary><div class="detail-content">'
        if ((${#MCP_NAMES[@]}>0)); then
            echo '<table><tr><th>Name</th><th>Command</th><th>Args</th><th>Env Vars</th></tr>'
            for ((i=0;i<${#MCP_NAMES[@]};i++)); do
                printf '<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>\n' "$(_h "${MCP_NAMES[$i]}")" "$(_h "${MCP_CMDS[$i]}")" "$(_h "${MCP_ARGS_STR[$i]}")" "$(_h "${MCP_ENV_KEYS[$i]}")"
            done; echo '</table>'
            printf '<div class="finding">%s MCP servers execute with Claude'\''s permissions.</div>\n' "$(_badge_html "REVIEW")"
        else echo '<p>No MCP servers configured.</p>'; fi; echo '</div></details>'
    fi

    # Plugins
    local has_plg=false; ((n_inst>0||n_rem>0||n_cach>0)) && has_plg=true
    if [[ "$quiet" != "true" || "$has_plg" == "true" ]]; then
        echo '<details open><summary>Plugins</summary><div class="detail-content">'
        if ((n_inst>0)); then
            echo '<h3>Installed</h3><table><tr><th>Name</th><th>Version</th><th>Source</th><th>Scope</th><th>Installed</th></tr>'
            for ((i=0;i<${#PLG_SRCS[@]};i++)); do [[ "${PLG_SRCS[$i]}" != "installed" ]] && continue
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$(_h "${PLG_NAMES[$i]}")" "$(_h "${PLG_VERS[$i]}")" "$(_h "${PLG_MPS[$i]}")" "$(_h "${PLG_SCOPES[$i]}")" "$(_h "${PLG_INSTALLED_ATS[$i]:0:10}")"
            done; echo '</table>'; fi
        if ((n_rem>0)); then
            echo '<h3>Remote (org-deployed)</h3><table><tr><th>Name</th><th>Version</th><th>Author</th><th>Marketplace</th><th>Skills</th></tr>'
            for ((i=0;i<${#PLG_SRCS[@]};i++)); do [[ "${PLG_SRCS[$i]}" != "remote" ]] && continue
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$(_h "${PLG_NAMES[$i]}")" "$(_h "${PLG_VERS[$i]}")" "$(_h "${PLG_AUTHORS[$i]}")" "$(_h "${PLG_MPS[$i]}")" "${PLG_SKILL_COUNTS[$i]}"
            done; echo '</table>'; fi
        if ((n_cach>0)); then
            echo '<h3>Cached</h3><table><tr><th>Name</th><th>Version</th><th>Author</th><th>Marketplace</th></tr>'
            for ((i=0;i<${#PLG_SRCS[@]};i++)); do [[ "${PLG_SRCS[$i]}" != "cached" ]] && continue
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$(_h "${PLG_NAMES[$i]}")" "$(_h "${PLG_VERS[$i]}")" "$(_h "${PLG_AUTHORS[$i]}")" "$(_h "${PLG_MPS[$i]}")"
            done; echo '</table>'; fi
        if [[ "$quiet" != "true" && ${#MARKETPLACE_AVAILABLE[@]} -gt 0 ]]; then
            local avail; avail=$(printf '%s\n' "${MARKETPLACE_AVAILABLE[@]}" | sort -u | tr '\n' ', ' | sed 's/,$//')
            printf '<h3>Available in marketplace</h3><p class="avail-list">%s</p>\n' "$(_h "$avail")"; fi
        [[ "$has_plg" == "false" ]] && echo '<p>No plugins found.</p>'; echo '</div></details>'
    fi

    # Connectors
    if [[ "$quiet" != "true" || $n_web -gt 0 || $n_nc -gt 0 ]]; then
        echo '<details open><summary>Connectors</summary><div class="detail-content">'
        if ((n_web>0)); then
            echo "<h3>Web ($n_web connected)</h3><table><tr><th>Connector</th><th>Tools</th></tr>"
            for ((i=0;i<${#CONN_CATS[@]};i++)); do [[ "${CONN_CATS[$i]}" != "web" ]] && continue
                printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(_h "${CONN_NAMES[$i]}")" "${CONN_TOOLS[$i]:-"-"}"
            done; echo '</table>'; fi
        local n_desk=0; for ((i=0;i<${#CONN_CATS[@]};i++)); do [[ "${CONN_CATS[$i]}" == "desktop" ]] && ((n_desk++)); done
        if ((n_desk>0)) && [[ "$quiet" != "true" ]]; then
            echo "<h3>Desktop ($n_desk)</h3><table><tr><th>Connector</th><th>Tags</th></tr>"
            for ((i=0;i<${#CONN_CATS[@]};i++)); do [[ "${CONN_CATS[$i]}" != "desktop" ]] && continue
                printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(_h "${CONN_NAMES[$i]}")" "$(_h "${CONN_TAGS[$i]:-"-"}")"
            done; echo '</table>'; fi
        if ((n_nc>0)); then
            echo "<h3>Not connected ($n_nc)</h3><table><tr><th>Connector</th></tr>"
            for ((i=0;i<${#CONN_CATS[@]};i++)); do [[ "${CONN_CATS[$i]}" != "not_connected" ]] && continue
                printf '<tr><td>%s</td></tr>\n' "$(_h "${CONN_NAMES[$i]}")"
            done; echo '</table>'; fi
        ((n_web==0&&n_nc==0)) && echo '<p>No connectors found.</p>'; echo '</div></details>'
    fi

    # Skills
    local n_usk=0 n_psk=0
    for ((i=0;i<${#SK_SRCS[@]};i++)); do [[ "${SK_SRCS[$i]}" == "user" ]] && ((n_usk++)) || ((n_psk++)); done
    if [[ "$quiet" != "true" || $n_usk -gt 0 || $n_psk -gt 0 ]]; then
        echo '<details open><summary>Skills</summary><div class="detail-content">'
        if ((n_usk>0)); then
            echo '<h3>User-created</h3><table><tr><th>Name</th><th>Description</th><th>Path</th></tr>'
            for ((i=0;i<${#SK_SRCS[@]};i++)); do [[ "${SK_SRCS[$i]}" != "user" ]] && continue
                printf '<tr><td>%s</td><td>%s</td><td><code>%s</code></td></tr>\n' "$(_h "${SK_NAMES[$i]}")" "$(_h "${SK_DESCS[$i]:0:80}")" "$(_h "${SK_PATHS[$i]}")"
            done; echo '</table>'; fi
        if ((n_psk>0)) && [[ "$quiet" != "true" ]]; then
            echo '<h3>Plugin skills</h3><table><tr><th>Skill</th><th>Plugin</th><th>Description</th></tr>'
            for ((i=0;i<${#SK_SRCS[@]};i++)); do [[ "${SK_SRCS[$i]}" != "plugin" ]] && continue
                printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$(_h "${SK_NAMES[$i]}")" "$(_h "${SK_PLUGINS[$i]:-unknown}")" "$(_h "${SK_DESCS[$i]:0:80}")"
            done; echo '</table>'
        elif ((n_psk>0)); then
            local -A pns; for ((i=0;i<${#SK_SRCS[@]};i++)); do [[ "${SK_SRCS[$i]}" == "plugin" ]] && pns["${SK_PLUGINS[$i]:-unknown}"]=1; done
            printf '<p>Plugin skills: %d across %s</p>\n' "$n_psk" "$(_h "$(IFS=', '; echo "${(k)pns[*]}")")"; fi
        ((n_usk==0&&n_psk==0)) && echo '<p>No skills found.</p>'; echo '</div></details>'
    fi

    # Scheduled Tasks
    local n_act=0; for ((i=0;i<${#ST_ENABLEDS[@]};i++)); do [[ "${ST_ENABLEDS[$i]}" == "true" ]] && ((n_act++)); done
    if [[ "$quiet" != "true" || $n_act -gt 0 ]]; then
        echo '<details open><summary>Scheduled Tasks</summary><div class="detail-content">'
        if ((${#ST_IDS[@]}>0)); then
            echo '<table><tr><th>Task ID</th><th>Cron</th><th>Schedule</th><th>Enabled</th><th>Description</th><th>Skill Path</th></tr>'
            for ((i=0;i<${#ST_IDS[@]};i++)); do
                [[ "$quiet" == "true" && "${ST_ENABLEDS[$i]}" != "true" ]] && continue
                local desc="${ST_SNAMES[$i]:-${ST_SDESCS[$i]:-${ST_PROMPTS[$i]:0:60}}}"
                local en='No'; [[ "${ST_ENABLEDS[$i]}" == "true" ]] && en='<span style="color:#28a745">Yes</span>'
                printf '<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>\n' "$(_h "${ST_IDS[$i]}")" "$(_h "${ST_CRONS[$i]}")" "$(_h "${ST_CRON_ENG[$i]}")" "$en" "$(_h "$desc")" "$(_h "${ST_FPATHS[$i]}")"
            done; echo '</table>'
        else echo '<p>No scheduled tasks found.</p>'; fi; echo '</div></details>'
    fi

    # Extensions
    if [[ "$quiet" != "true" || ${#EXT_NAMES[@]} -gt 0 ]]; then
        echo '<details open><summary>Extensions (DXT)</summary><div class="detail-content">'
        if ((${#EXT_NAMES[@]}>0)); then
            echo '<table><tr><th>Name</th><th>Version</th><th>Author</th><th>Signed</th><th>Dangerous Tools</th></tr>'
            for ((i=0;i<${#EXT_NAMES[@]};i++)); do
                [[ "$quiet" == "true" && "${EXT_SIGNEDS[$i]}" == "true" && -z "${EXT_DANGER_STR[$i]}" ]] && continue
                local sh; [[ "${EXT_SIGNEDS[$i]}" == "true" ]] && sh='<span style="color:#28a745">Yes</span>' || sh='<span style="color:#ffc107">No</span>'
                local dh="-"; if [[ -n "${EXT_DANGER_STR[$i]}" ]]; then dh=""; IFS=',' read -rA dt <<< "${EXT_DANGER_STR[$i]}"; for t in "${dt[@]}"; do dh+="<code>$(_h "$t")</code> "; done; fi
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$(_h "${EXT_NAMES[$i]}")" "$(_h "${EXT_VERS[$i]}")" "$(_h "${EXT_AUTHORS[$i]}")" "$sh" "$dh"
            done; echo '</table>'
        else echo '<p>No DXT extensions installed.</p>'; fi; echo '</div></details>'
    fi

    # Security Findings
    echo '<details open><summary>Security Findings</summary><div class="detail-content">'
    local fany=false
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        [[ "${FINDING_SECT[$i]}" != "Security" ]] && continue
        [[ "$quiet" == "true" && "${FINDING_SEV[$i]}" != "CRITICAL" && "${FINDING_SEV[$i]}" != "WARN" ]] && continue
        printf '<div class="finding">%s %s</div>\n' "$(_badge_html "${FINDING_SEV[$i]}")" "$(_h "${FINDING_MSG[$i]}")"; fany=true
    done
    local has_pt=false; local -A psh
    for ((i=0;i<${#FP_STATS[@]};i++)); do
        [[ "${FP_STATS[$i]}" == "OK" || -n "${psh[${FP_PATHS[$i]}]:-}" ]] && continue
        [[ "$has_pt" == "true" ]] || { echo '<table><tr><th>File</th><th>Mode</th><th>Issue</th></tr>'; has_pt=true; fany=true; }
        psh["${FP_PATHS[$i]}"]=1
        printf '<tr><td><code>%s</code></td><td>%s</td><td style="color:#ffc107">%s</td></tr>\n' "$(_h "$(basename "${FP_PATHS[$i]}")")" "$(_h "${FP_MODES[$i]}")" "$(_h "${FP_STATS[$i]}")"
    done; [[ "$has_pt" == "true" ]] && echo '</table>'
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        [[ "${FINDING_SECT[$i]}" == "Runtime" && "${FINDING_SEV[$i]}" != "INFO" && "${FINDING_SEV[$i]}" != "OK" ]] && {
            printf '<div class="finding">%s %s</div>\n' "$(_badge_html "${FINDING_SEV[$i]}")" "$(_h "${FINDING_MSG[$i]}")"; fany=true; }
    done
    [[ "$fany" == "true" ]] || echo '<p style="color:#28a745">No security issues detected.</p>'; echo '</div></details>'

    # Recommendations
    echo '<details open><summary>Recommendations</summary><div class="detail-content">'
    if ((${#RECOMMENDATIONS[@]}>0)); then echo '<ol>'
        for ((i=0;i<${#RECOMMENDATIONS[@]};i++)); do printf '<li style="margin-bottom:8px;">%s</li>\n' "$(_h "${RECOMMENDATIONS[$i]}")"; done
        echo '</ol>'
    else echo '<p style="color:#28a745">No issues requiring action.</p>'; fi; echo '</div></details>'

    if [[ "$quiet" != "true" ]]; then
        echo '<details><summary>Runtime Info</summary><div class="detail-content">'
        for ((i=0;i<${#FINDING_SEV[@]};i++)); do [[ "${FINDING_SECT[$i]}" == "Runtime" ]] && printf '<div class="finding">%s %s</div>\n' "$(_badge_html "${FINDING_SEV[$i]}")" "$(_h "${FINDING_MSG[$i]}")"; done
        [[ -n "${RUNTIME_INFO[ant_did]:-}" ]] && printf '<div>Device ID: <code>%s</code></div>\n' "$(_h "${RUNTIME_INFO[ant_did]}")"
        echo '</div></details>'
    fi
    printf '<p class="meta" style="margin-top:30px;">CLAUDIT v%s &mdash; read-only audit, no files modified.</p>\n</div></body></html>\n' "$VERSION"
}

# ── JSON Renderer ─────────────────────────────────────────────────────────────
_jstr() { printf '"%s"' "$(json_escape "$1")"; }

render_json() {
    local i
    local findings_j="["; for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        ((i>0)) && findings_j+=","
        findings_j+="{\"severity\":$(_jstr "${FINDING_SEV[$i]}"),\"section\":$(_jstr "${FINDING_SECT[$i]}"),\"message\":$(_jstr "${FINDING_MSG[$i]}"),\"detail\":$(_jstr "${FINDING_DET[$i]}")}"
    done; findings_j+="]"

    local mcp_j="["; for ((i=0;i<${#MCP_NAMES[@]};i++)); do ((i>0)) && mcp_j+=","
        mcp_j+="{\"name\":$(_jstr "${MCP_NAMES[$i]}"),\"command\":$(_jstr "${MCP_CMDS[$i]}"),\"args\":$(_jstr "${MCP_ARGS_STR[$i]}"),\"env_keys\":$(_jstr "${MCP_ENV_KEYS[$i]}")}"
    done; mcp_j+="]"

    local plg_j="["; for ((i=0;i<${#PLG_NAMES[@]};i++)); do ((i>0)) && plg_j+=","
        plg_j+="{\"name\":$(_jstr "${PLG_NAMES[$i]}"),\"version\":$(_jstr "${PLG_VERS[$i]}"),\"source\":$(_jstr "${PLG_SRCS[$i]}"),\"author\":$(_jstr "${PLG_AUTHORS[$i]}"),\"marketplace\":$(_jstr "${PLG_MPS[$i]}"),\"skill_count\":${PLG_SKILL_COUNTS[$i]:-0}}"
    done; plg_j+="]"

    local conn_j="["; for ((i=0;i<${#CONN_NAMES[@]};i++)); do ((i>0)) && conn_j+=","
        conn_j+="{\"name\":$(_jstr "${CONN_NAMES[$i]}"),\"category\":$(_jstr "${CONN_CATS[$i]}"),\"tool_count\":${CONN_TOOLS[$i]:-0}}"
    done; conn_j+="]"

    local sk_j="["; for ((i=0;i<${#SK_NAMES[@]};i++)); do ((i>0)) && sk_j+=","
        sk_j+="{\"name\":$(_jstr "${SK_NAMES[$i]}"),\"description\":$(_jstr "${SK_DESCS[$i]}"),\"source\":$(_jstr "${SK_SRCS[$i]}"),\"plugin_name\":$(_jstr "${SK_PLUGINS[$i]}")}"
    done; sk_j+="]"

    local st_j="["; for ((i=0;i<${#ST_IDS[@]};i++)); do ((i>0)) && st_j+=","
        st_j+="{\"task_id\":$(_jstr "${ST_IDS[$i]}"),\"cron_expression\":$(_jstr "${ST_CRONS[$i]}"),\"cron_english\":$(_jstr "${ST_CRON_ENG[$i]}"),\"enabled\":${ST_ENABLEDS[$i]},\"file_path\":$(_jstr "${ST_FPATHS[$i]}"),\"skill_name\":$(_jstr "${ST_SNAMES[$i]}")}"
    done; st_j+="]"

    local ext_j="["; for ((i=0;i<${#EXT_NAMES[@]};i++)); do ((i>0)) && ext_j+=","
        ext_j+="{\"ext_id\":$(_jstr "${EXT_IDS[$i]}"),\"name\":$(_jstr "${EXT_NAMES[$i]}"),\"version\":$(_jstr "${EXT_VERS[$i]}"),\"author\":$(_jstr "${EXT_AUTHORS[$i]}"),\"signed\":${EXT_SIGNEDS[$i]},\"signature_status\":$(_jstr "${EXT_SIG_STATS[$i]}"),\"dangerous_tools\":$(_jstr "${EXT_DANGER_STR[$i]}")}"
    done; ext_j+="]"

    local fp_j="["; for ((i=0;i<${#FP_PATHS[@]};i++)); do ((i>0)) && fp_j+=","
        fp_j+="{\"path\":$(_jstr "${FP_PATHS[$i]}"),\"mode\":$(_jstr "${FP_MODES[$i]}"),\"status\":$(_jstr "${FP_STATS[$i]}")}"
    done; fp_j+="]"

    local dp_j="{\"keepAwakeEnabled\":${DESKTOP_PREFS[keepAwakeEnabled]:-false},\"menuBarEnabled\":${DESKTOP_PREFS[menuBarEnabled]:-false}}"
    local cp_j="{\"coworkScheduledTasksEnabled\":${COWORK_PREFS[coworkScheduledTasksEnabled]:-false},\"ccdScheduledTasksEnabled\":${COWORK_PREFS[ccdScheduledTasksEnabled]:-false},\"coworkWebSearchEnabled\":${COWORK_PREFS[coworkWebSearchEnabled]:-false}}"

    printf '{"timestamp":%s,"hostname":%s,"username":%s,"home_dir":%s,"findings":%s,"desktop_prefs":%s,"cowork_prefs":%s,"cowork_network_mode":%s,"mcp_servers":%s,"plugins":%s,"connectors":%s,"skills":%s,"scheduled_tasks":%s,"extensions":%s,"blocklist_entries":%d,"blocklist_status":%s,"claude_code_settings":%s,"file_permissions":%s,"warn_count":%d,"info_count":%d,"critical_count":%d}' \
        "$(_jstr "$TIMESTAMP")" "$(_jstr "$HOSTNAME_VAL")" "$(_jstr "$AUDIT_USER")" "$(_jstr "$HOME_DIR")" \
        "$findings_j" "$dp_j" "$cp_j" "$(_jstr "$COWORK_NETWORK_MODE")" \
        "$mcp_j" "$plg_j" "$conn_j" "$sk_j" "$st_j" "$ext_j" \
        "$BLOCKLIST_ENTRIES" "$(_jstr "$BLOCKLIST_STATUS")" "$CLAUDE_CODE_JSON" "$fp_j" \
        "$WARN_COUNT" "$INFO_COUNT" "$CRITICAL_COUNT" | \
    jq 'def redact: if type=="object" then to_entries|map(if .key|test("oauth|token|tokenCache|secret|password|credential|apiKey|api_key|access_token|refresh_token|private_key|privateKey";"i") then .value="[REDACTED]" else .value=(.value|redact) end)|from_entries elif type=="array" then map(redact) else . end; redact'
}

# ── Run Audit ─────────────────────────────────────────────────────────────────
run_audit() {
    local username="$1" home="$2"
    AUDIT_USER="$username"; HOME_DIR="$home"
    HOSTNAME_VAL=$(hostname -s 2>/dev/null || hostname)
    TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S') $(date +%Z 2>/dev/null || true)"

    FINDING_SEV=(); FINDING_SECT=(); FINDING_MSG=(); FINDING_DET=()
    MCP_NAMES=(); MCP_CMDS=(); MCP_ARGS_STR=(); MCP_ENV_KEYS=()
    PLG_NAMES=(); PLG_VERS=(); PLG_SRCS=(); PLG_SCOPES=(); PLG_AUTHORS=()
    PLG_DESCS=(); PLG_MPS=(); PLG_INSTALLED_ATS=(); PLG_INSTALLED_BYS=()
    PLG_IDS=(); PLG_SKILL_COUNTS=(); MARKETPLACE_AVAILABLE=()
    CONN_NAMES=(); CONN_CATS=(); CONN_TOOLS=(); CONN_TAGS=()
    SK_NAMES=(); SK_DESCS=(); SK_SRCS=(); SK_PLUGINS=(); SK_PATHS=()
    ST_IDS=(); ST_CRONS=(); ST_CRON_ENG=(); ST_ENABLEDS=(); ST_FPATHS=()
    ST_CREATED=(); ST_SNAMES=(); ST_SDESCS=(); ST_PROMPTS=()
    EXT_IDS=(); EXT_NAMES=(); EXT_VERS=(); EXT_AUTHORS=(); EXT_SIGNEDS=()
    EXT_SIG_STATS=(); EXT_TOOLS_STR=(); EXT_DANGER_STR=(); EXT_INST_ATS=(); EXT_DESCS=()
    FP_PATHS=(); FP_MODES=(); FP_STATS=()
    BLOCKLIST_ENTRIES=0; BLOCKLIST_STATUS=""; CLAUDE_CODE_JSON="{}"
    COWORK_ENABLED_PLUGINS=(); COWORK_NETWORK_MODE=""; RECOMMENDATIONS=()
    declare -gA DESKTOP_PREFS=() COWORK_PREFS=() APP_CONFIG=() RUNTIME_INFO=() COOKIES_INFO=()
    declare -gA EXT_SETTINGS_JSON=() COWORK_MARKETPLACES_JSON=()

    local claude_dir="$home/$CLAUDE_DESKTOP_DIR"
    [[ -d "$claude_dir" ]] || add_finding "INFO" "General" "Claude Desktop directory not found: $claude_dir"
    find_session_dirs "$claude_dir"

    collect_desktop_settings "$claude_dir"
    collect_cowork_settings
    collect_app_config "$claude_dir"
    collect_extensions "$claude_dir"
    collect_extension_settings "$claude_dir"
    collect_plugins
    collect_connectors
    collect_skills "$home"
    collect_scheduled_tasks
    collect_blocklist "$claude_dir"
    collect_claude_code_settings "$home"
    collect_file_permissions "$claude_dir" "$home"
    collect_runtime "$claude_dir" "$home"
    collect_cookies "$claude_dir"

    WARN_COUNT=0; INFO_COUNT=0; CRITICAL_COUNT=0
    for ((i=0;i<${#FINDING_SEV[@]};i++)); do
        case "${FINDING_SEV[$i]}" in WARN) ((WARN_COUNT++));; INFO) ((INFO_COUNT++));; CRITICAL) ((CRITICAL_COUNT++));; esac
    done
    build_recommendations
}

# ── CLI ───────────────────────────────────────────────────────────────────────
OPT_HTML="" ; OPT_JSON=false ; OPT_USER="" ; OPT_ALL_USERS=false ; OPT_QUIET=false

while [[ $# -gt 0 ]]; do case "$1" in
    --html) if [[ $# -gt 1 && "$2" != -* ]]; then OPT_HTML="$2"; shift 2; else OPT_HTML="AUTO"; shift; fi ;;
    --json) OPT_JSON=true; shift ;; --user) OPT_USER="${2:?--user requires argument}"; shift 2 ;;
    --all-users) OPT_ALL_USERS=true; shift ;; -q|--quiet) OPT_QUIET=true; shift ;;
    --version) echo "CLAUDIT v${VERSION}"; exit 0 ;;
    -h|--help) echo "CLAUDIT v${VERSION} — Claude Security Audit"; echo "Usage: $0 [--html [FILE]] [--json] [--user USER] [--all-users] [-q] [--version]"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;; esac
done

[[ -n "$OPT_USER" && "$OPT_ALL_USERS" == "true" ]] && { echo "Error: --user and --all-users are mutually exclusive" >&2; exit 1; }

detect_user_contexts

_json_multi=$([[ "$OPT_JSON" == "true" && ${#USER_CONTEXTS[@]} -gt 1 ]] && echo true || echo false)
$_json_multi && printf '['
_json_first=true

for ctx in "${USER_CONTEXTS[@]}"; do
    IFS='|' read -r ctx_user ctx_home <<< "$ctx"
    run_audit "$ctx_user" "$ctx_home"

    if [[ "$OPT_JSON" == "true" ]]; then
        $_json_multi && { $_json_first || printf ','; _json_first=false; }
        render_json
    elif [[ -n "$OPT_HTML" ]]; then
        filename=""
        if [[ "$OPT_HTML" == "AUTO" ]]; then filename="claude_audit_${ctx_user}_$(date '+%Y%m%d_%H%M%S').html"
        elif ((${#USER_CONTEXTS[@]} > 1)); then
            base="${OPT_HTML%.*}"; ext="${OPT_HTML##*.}"
            [[ "$base" == "$OPT_HTML" ]] && ext=""; filename="${base}_${ctx_user}${ext:+.$ext}"
        else filename="$OPT_HTML"; fi
        (umask 077; render_html "$OPT_QUIET" > "$filename")
        echo "HTML report written to: $filename" >&2
    else
        render_ascii "$OPT_QUIET"
    fi
done

[[ "$_json_multi" == "true" ]] && printf ']'
exit 0
