#!/usr/bin/env bash
# test-rpc.sh — Integration tests for openmediavault-filemanager RPC methods.
#
# Usage: sudo ./tests/test-rpc.sh <sharedfolder> [<username>]
#
# Exercises all FileManager RPC methods against a temporary test folder
# created inside the given shared folder: settings, listing, path
# confinement, create/rename, editor (incl. conflict detection), trash,
# search, copy/move, archives, symlinks pointing out of the shared folder,
# permissions, properties, checksums, download/preview (incl. security
# headers), chunked upload, download from URL (incl. blocking of local
# addresses), duplicate, symbolic links, disk usage, 7z/ISO extraction, the
# trash overview and cleanup, share links (incl. the isolated share link
# server: downloads, passwords, limits, privilege separation), the audit
# log and the access checks (read-only mode, exposed shared folders,
# disabled, file system permissions of non-administrative users).
#
# Prerequisites:
#   <sharedfolder> — name or UUID of an existing OMV shared folder that is
#                    not located at the root of the OS
#   <username>     — optional system user with read-only (5) or read-write
#                    (7) privileges on that shared folder; enables the
#                    non-administrator tests
#
# Find values with:
#   omv-rpc -u admin ShareMgmt getList \
#     '{"start":0,"limit":25,"sortfield":null,"sortdir":null}'
#
# The test folder, its trash entries and all temporary files are removed and
# the original FileManager settings are restored on exit. "Empty trash" is
# only tested if the shared folder has no '.recycle' folder yet, so existing
# (e.g. Samba) recycle bin contents are never touched.
#
# WARNING: This script transiently modifies the FileManager settings and
# starts the share link server on a free port. Run on a test system or
# during a maintenance window.

set -uo pipefail

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
if [ $# -lt 1 ]; then
    echo "Usage: $(basename "$0") <sharedfolder> [<username>]" >&2
    echo "" >&2
    echo "  <sharedfolder>  name or UUID of an OMV shared folder" >&2
    echo "  <username>      optional user with read or write access to that folder" >&2
    echo "" >&2
    echo "  Find shared folders:" >&2
    echo "    omv-rpc -u admin ShareMgmt getList" \
         "'{\"start\":0,\"limit\":25,\"sortfield\":null,\"sortdir\":null}'" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

SF_REF="$1"
TEST_USER="${2:-}"

# ---------------------------------------------------------------------------
# Colours / counters  (display → stderr; $() captures only JSON)
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
declare -a FAILED_TESTS=()

section() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}" >&2; }
info()    { echo -e "  ${YELLOW}»${NC} $*" >&2; }

_pass() {
    echo -e "  ${GREEN}PASS${NC}  $1" >&2
    ((PASS++)) || true
}
_fail() {
    echo -e "  ${RED}FAIL${NC}  $1" >&2
    [ -n "${2:-}" ] && echo -e "         ${RED}→${NC} $2" >&2
    ((FAIL++)) || true
    FAILED_TESTS+=("$1")
}

# Assert a shell condition. $1 description, rest the command to evaluate.
check() {
    local desc=$1
    shift
    if "$@"; then
        _pass "$desc"
    else
        _fail "$desc"
    fi
}

# Assert a jq filter holds for a JSON document. $1 description, $2 JSON,
# $3 filter, rest extra jq arguments (e.g. --arg).
jcheck() {
    local desc=$1 json=$2 filter=$3
    shift 3
    if echo "$json" | jq -e "$@" "$filter" &>/dev/null; then
        _pass "$desc"
    else
        _fail "$desc" "jq '$filter' did not hold"
    fi
}

# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------
RPC_USER="admin"

rpc() {
    local svc=$1 method=$2 params=${3:-'{}'}
    omv-rpc -u "$RPC_USER" "$svc" "$method" "$params"
}

assert_rpc() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-}
    local out ec=0
    out=$(omv-rpc -u "$RPC_USER" "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -ne 0 ]; then
        _fail "$desc" "$(echo "$out" | jq -r '.error.message // empty' 2>/dev/null \
            || echo "$out" | tail -3)"
        return 1
    fi
    # omv-rpc escapes slashes in its JSON output ("\/").
    if [ -n "$pattern" ] && ! echo "${out//\\\//\/}" | grep -q -- "$pattern"; then
        _fail "$desc" "Pattern '$pattern' not found in: ${out:0:200}"
        return 1
    fi
    _pass "$desc"
    OUT=$out
    return 0
}

# Assert an RPC call fails. Optional 5th arg: pattern the error must match
# (case-insensitive).
assert_rpc_fails() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-}
    local out ec=0 msg
    out=$(omv-rpc -u "$RPC_USER" "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -eq 0 ] && ! echo "$out" | grep -qi "exception"; then
        _fail "$desc" "Expected failure but RPC succeeded: ${out:0:200}"
        return 1
    fi
    msg=$(echo "$out" | jq -r '.error.message // empty' 2>/dev/null || true)
    [ -n "$msg" ] || msg=$(echo "$out" | tail -1)
    if [ -n "$pattern" ] && ! echo "$msg" | grep -qi -- "$pattern"; then
        _fail "$desc" "Error did not match '$pattern': ${msg:0:200}"
        return 1
    fi
    _pass "$desc [${msg:0:80}]"
    return 0
}

# Wait until a background job finished, then echo its output. $1 is the raw
# JSON string returned by an execBgProc RPC, $2 the timeout in seconds.
# Only Exec.getOutput is polled: Exec.isRunning deletes the status file of a
# finished job. A failed job makes getOutput throw instead of returning its
# output, so the error message is echoed as "ERROR: <message>".
# Returns 1 if the job is still running after the timeout.
wait_bgproc() {
    local raw=$1 timeout=${2:-60} filename pos=0 resp state
    filename=$(echo "$raw" | jq -r '.' 2>/dev/null || echo "")
    [ -n "$filename" ] || return 1
    for _ in $(seq 1 "$timeout"); do
        resp=$(omv-rpc -u "$RPC_USER" "Exec" "getOutput" \
            "{\"filename\":\"$filename\",\"pos\":$pos}" 2>&1 || true)
        # Prints the new output, then a last line "<state> <pos>".
        state=$(echo "$resp" | POS_ENV=$pos python3 -c "
import sys, json, os
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except ValueError:
    d = {'error': {'message': raw.strip()}}
if isinstance(d, dict) and d.get('error'):
    print('ERROR: ' + str(d['error'].get('message', '')))
    print('done ' + os.environ['POS_ENV'])
else:
    d = d.get('response', d) if isinstance(d, dict) else {}
    out = d.get('output', '')
    sys.stdout.write(out if not out or out.endswith(chr(10)) else out + chr(10))
    print(('running ' if d.get('running') else 'done ') + str(d.get('pos', 0)))
" 2>/dev/null || echo "done $pos")
        echo "$state" | sed '$d'
        pos=$(echo "$state" | tail -1 | cut -d' ' -f2)
        [ "$(echo "$state" | tail -1 | cut -d' ' -f1)" = "done" ] && return 0
        sleep 1
    done
    return 1
}

# Run a background RPC and assert its outcome.
#   $1 description, $2 method, $3 params, $4 "ok" or "fail",
#   $5 optional pattern the output must contain.
# Echoes the job output.
assert_bg() {
    local desc=$1 method=$2 params=$3 expect=${4:-ok} pattern=${5:-}
    local raw out ec=0
    raw=$(omv-rpc -u "$RPC_USER" "FileManager" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -ne 0 ]; then
        if [ "$expect" = "fail" ]; then
            _pass "$desc [$(echo "$raw" | jq -r '.error.message // empty' 2>/dev/null | cut -c1-80)]"
        else
            _fail "$desc" "$(echo "$raw" | jq -r '.error.message // empty' 2>/dev/null)"
        fi
        return 0
    fi
    if ! out=$(wait_bgproc "$raw" 120); then
        _fail "$desc" "background job did not finish in time"
        return 1
    fi
    if [ "$expect" = "ok" ] && echo "$out" | grep -q "^ERROR: "; then
        _fail "$desc" "$(echo "$out" | grep "^ERROR: " | head -1)"
    elif [ "$expect" = "fail" ] && ! echo "$out" | grep -q "^ERROR: "; then
        _fail "$desc" "Expected the job to fail: ${out:0:200}"
    elif [ -n "$pattern" ] && ! echo "$out" | grep -q -- "$pattern"; then
        _fail "$desc" "Pattern '$pattern' not found in: ${out:0:300}"
    else
        _pass "$desc"
    fi
    echo "$out"
}

# Path token as used by the plugin: base64url without padding; the shared
# folder root is the literal "root".
tok() {
    if [ "$1" = "." ] || [ -z "$1" ]; then
        echo "root"
    else
        printf '%s' "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='
    fi
}

# getList params for a path relative to the shared folder.
list_params() {
    echo "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$1")\",\"start\":0,\"limit\":null,\"sortfield\":\"name\",\"sortdir\":\"asc\"}"
}

# Names returned by a list response, one per line.
names() { jq -r '.data[].name'; }

# Apply settings on top of the test baseline. $1 jq filter, e.g.
# '.readonly = true'; '.' restores the baseline.
set_settings() {
    local s
    s=$(echo "$BASE_SETTINGS" | jq -c "$1")
    omv-rpc -u admin "FileManager" "setSettings" "$s" &>/dev/null
}

# Create an upload chunk the way PHP-FPM does: /tmp/phpXXXXXX owned by the
# WebGUI user. $1 content. Echoes the file name.
make_chunk() {
    local f
    f=$(mktemp /tmp/phpXXXXXX)
    printf '%s' "$1" > "$f"
    chown "$WEBGUI_USER" "$f"
    chmod 600 "$f"
    CHUNKS+=("$f")
    echo "$f"
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
SF_UUID=""
SF_NAME=""
SF_PATH=""
TEST_NAME="fm-rpctest-$$"
TEST_DIR=""
ORIG_SETTINGS=""
BASE_SETTINGS=""
TRASH_EXISTED=true
OUTSIDE_DIR=""
IMMUTABLE=""
START_TS=$(date '+%Y-%m-%d %H:%M:%S')
WEBGUI_USER=$(. /etc/default/openmediavault 2>/dev/null; \
    echo "${OMV_WEBGUI_FILE_OWNERGROUP_NAME:-openmediavault-webgui}")
declare -a CHUNKS=()
declare -a STAGED=()
declare -a SHARE_TOKENS=()
SHARE_PORT=""

GETLIST='{"start":0,"limit":null,"sortfield":"name","sortdir":"asc"}'

# ---------------------------------------------------------------------------
# Cleanup — always runs on exit
# ---------------------------------------------------------------------------
cleanup() {
    section "Cleanup"

    # Also remove links into test folders that were left behind, e.g. by
    # an aborted run. Deleting needs the file manager to be enabled.
    local t tokens
    [ -n "$BASE_SETTINGS" ] && set_settings '.'
    tokens=$(omv-rpc -u admin "FileManager" "getShareLinkList" "$GETLIST" 2>/dev/null \
        | jq -r '.data[] | select(.location | startswith("/fm-rpctest-")) | .token' \
        2>/dev/null) || true
    for t in "${SHARE_TOKENS[@]}" $tokens; do
        omv-rpc -u admin "FileManager" "deleteShareLink" "{\"token\":\"$t\"}" \
            &>/dev/null || true
    done

    if [ -n "$ORIG_SETTINGS" ]; then
        info "Restoring original FileManager settings"
        omv-rpc -u admin "FileManager" "setSettings" "$ORIG_SETTINGS" \
            &>/dev/null || true
    fi

    [ -n "$IMMUTABLE" ] && chattr -i -- "$IMMUTABLE" 2>/dev/null
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        info "Removing test folder $TEST_DIR"
        rm -rf --one-file-system -- "$TEST_DIR"
    fi

    if [ -n "$SF_PATH" ] && [ -d "$SF_PATH/.recycle" ]; then
        if ! $TRASH_EXISTED; then
            info "Removing trash folder created by the test"
            rm -rf --one-file-system -- "$SF_PATH/.recycle"
        else
            info "Removing test items from the trash"
            find "$SF_PATH/.recycle" -mindepth 2 -maxdepth 2 \
                -name "$TEST_NAME*" -exec rm -rf --one-file-system -- {} + \
                2>/dev/null || true
        fi
    fi

    [ -n "$OUTSIDE_DIR" ] && rm -rf -- "$OUTSIDE_DIR"
    for f in "${CHUNKS[@]}" "${STAGED[@]}"; do
        rm -f -- "$f"
    done

    info "Done."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
section "Pre-flight"

for cmd in omv-rpc jq python3 base64 journalctl sha256sum md5sum curl bsdtar; do
    if command -v "$cmd" &>/dev/null; then
        _pass "command available: $cmd"
    else
        _fail "command available: $cmd" "$cmd not found"
    fi
done

if ! omv-rpc -u admin "Config" "isDirty" '{}' &>/dev/null; then
    echo -e "\n${RED}omv-rpc not functional — aborting.${NC}" >&2
    exit 1
fi
_pass "omv-rpc functional"

if ! omv-rpc -u admin "FileManager" "getSettings" '{}' &>/dev/null; then
    echo -e "\n${RED}FileManager RPC not available — is the plugin installed? Aborting.${NC}" >&2
    exit 1
fi
_pass "FileManager RPC available"

# Resolve shared folder — accept either a UUID or a name
if echo "$SF_REF" | grep -qE \
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    SF_UUID="$SF_REF"
else
    SF_UUID=$(omv-rpc -u admin "ShareMgmt" "getList" \
        '{"start":0,"limit":null,"sortfield":null,"sortdir":null}' 2>/dev/null \
        | jq -r --arg n "$SF_REF" '.data[] | select(.name == $n) | .uuid' \
        | head -1)
fi
SF_JSON=$(omv-rpc -u admin "ShareMgmt" "get" "{\"uuid\":\"$SF_UUID\"}" 2>/dev/null) || SF_JSON=""
if [ -z "$SF_UUID" ] || [ -z "$SF_JSON" ]; then
    echo -e "\n${RED}Shared folder '$SF_REF' not found — aborting.${NC}" >&2
    echo "  omv-rpc -u admin ShareMgmt getList" \
         "'{\"start\":0,\"limit\":25,\"sortfield\":null,\"sortdir\":null}'" >&2
    exit 1
fi
SF_NAME=$(echo "$SF_JSON" | jq -r '.name')
SF_PATH=$(omv-rpc -u admin "ShareMgmt" "getPath" "{\"uuid\":\"$SF_UUID\"}" | jq -r '.')
SF_PATH=$(realpath "$SF_PATH")
if [ "$SF_PATH" = "/" ] || [ ! -d "$SF_PATH" ]; then
    echo -e "\n${RED}Shared folder path '$SF_PATH' is unusable (missing or OS root) — aborting.${NC}" >&2
    exit 1
fi
_pass "shared folder found: $SF_NAME ($SF_UUID) at $SF_PATH"
[ -e "$SF_PATH/.recycle" ] || TRASH_EXISTED=false

USER_PERMS=""
if [ -n "$TEST_USER" ]; then
    if ! id "$TEST_USER" &>/dev/null; then
        echo -e "\n${RED}User '$TEST_USER' not found on this system — aborting.${NC}" >&2
        exit 1
    fi
    USER_PERMS=$(echo "$SF_JSON" | jq -r --arg u "$TEST_USER" \
        '.privileges.privilege
         | if type == "object" then [.] else . end
         | .[] | select(.type == "user" and .name == $u) | .perms' | head -1)
    if [ "$USER_PERMS" != "5" ] && [ "$USER_PERMS" != "7" ]; then
        echo -e "\n${RED}User '$TEST_USER' has no explicit read-only or read-write privilege on '$SF_NAME' — aborting.${NC}" >&2
        echo "  Grant via OMV → Storage → Shared Folders → Privileges." >&2
        exit 1
    fi
    _pass "user '$TEST_USER' has privilege $USER_PERMS on '$SF_NAME'"
fi

section "Configuration"
info "Shared folder : $SF_NAME  ($SF_UUID)"
info "Path          : $SF_PATH"
info "Test folder   : $TEST_NAME"
info "Username      : ${TEST_USER:-<none, non-admin tests skipped>}"
$TRASH_EXISTED && info "'.recycle' exists already — 'emptyTrash' will be skipped"

# ===========================================================================
section "Settings"
# ===========================================================================

assert_rpc "getSettings" "FileManager" "getSettings" || {
    echo -e "\n${RED}getSettings failed — aborting.${NC}" >&2
    exit 1
}
ORIG_SETTINGS=$(echo "$OUT" | jq -c '.')
for field in enable readonly showhidden maxeditsize sharedfolders usetrash auditlog allowusers \
        trashretention sharelinks shareusers shareport sharesslcertificateref shareurl; do
    if echo "$ORIG_SETTINGS" | jq -e "has(\"$field\")" &>/dev/null; then
        _pass "getSettings — field '$field' present"
    else
        _fail "getSettings — field '$field' missing"
    fi
done
check "getSettings — sharedfolders is an array" \
    test "$(echo "$ORIG_SETTINGS" | jq -r '.sharedfolders | type')" = "array"

# A free port for the share link server.
SHARE_PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1])')

# Known baseline for the tests: everything on, 1 MiB editor limit, share
# links off.
BASE_SETTINGS=$(echo "$ORIG_SETTINGS" | jq -c --argjson port "$SHARE_PORT" \
    '.enable = true | .readonly = false |
    .showhidden = true | .maxeditsize = 1 | .sharedfolders = [] |
    .usetrash = true | .auditlog = true | .allowusers = false |
    .trashretention = 0 | .sharelinks = false | .shareusers = false |
    .shareport = $port | .sharesslcertificateref = "" | .shareurl = ""')
assert_rpc "setSettings — test baseline" "FileManager" "setSettings" "$BASE_SETTINGS" \
    '"maxeditsize":1' >/dev/null
assert_rpc_fails "setSettings — maxeditsize 0 rejected" "FileManager" "setSettings" \
    "$(echo "$BASE_SETTINGS" | jq -c '.maxeditsize = 0')"
assert_rpc_fails "setSettings — invalid shared folder UUID rejected" "FileManager" \
    "setSettings" "$(echo "$BASE_SETTINGS" | jq -c '.sharedfolders = ["nope"]')"
assert_rpc "setSettings — select shared folder" "FileManager" "setSettings" \
    "$(echo "$BASE_SETTINGS" | jq -c --arg u "$SF_UUID" '.sharedfolders = [$u]')" \
    "$SF_UUID" >/dev/null
assert_rpc "setSettings — all shared folders again" "FileManager" "setSettings" \
    "$BASE_SETTINGS" '"sharedfolders":\[\]' >/dev/null
WEBGUI_PORT=$(omv-rpc -u admin "WebGui" "getSettings" '{}' 2>/dev/null | jq -r '.port // 80')
assert_rpc_fails "setSettings — share port of the web interface rejected" "FileManager" \
    "setSettings" "$(echo "$BASE_SETTINGS" | jq -c --argjson p "${WEBGUI_PORT:-80}" '.shareport = $p')"
assert_rpc_fails "setSettings — privileged share port rejected" "FileManager" \
    "setSettings" "$(echo "$BASE_SETTINGS" | jq -c '.shareport = 443')"
assert_rpc_fails "setSettings — invalid public URL rejected" "FileManager" \
    "setSettings" "$(echo "$BASE_SETTINGS" | jq -c '.shareurl = "ftp://x"')"
assert_rpc_fails "setSettings — negative trash retention rejected" "FileManager" \
    "setSettings" "$(echo "$BASE_SETTINGS" | jq -c '.trashretention = -1')"
assert_rpc "setSettings — public URL trimmed" "FileManager" "setSettings" \
    "$(echo "$BASE_SETTINGS" | jq -c '.shareurl = " https://files.example.com/x/ "')" \
    '"shareurl":"https://files.example.com/x"' >/dev/null
set_settings '.'

# ===========================================================================
section "Shared folders & enumerations"
# ===========================================================================

assert_rpc "getSharedFolderList" "FileManager" "getSharedFolderList" "$GETLIST" && {
    check "getSharedFolderList — contains '$SF_NAME' (rw)" \
        test "$(echo "$OUT" | jq -r --arg u "$SF_UUID" '.data[] | select(.uuid == $u) | .access')" = "rw"
    check "getSharedFolderList — trash token" \
        test "$(echo "$OUT" | jq -r --arg u "$SF_UUID" '.data[] | select(.uuid == $u) | .trashpath')" = "$(tok .recycle)"
}
assert_rpc "enumerateSharedFolders" "FileManager" "enumerateSharedFolders" && \
    jcheck "enumerateSharedFolders — contains '$SF_NAME'" "$OUT" \
        'any(.[]; .uuid == $u)' --arg u "$SF_UUID"
assert_rpc "enumerateBrowsableFolders" "FileManager" "enumerateBrowsableFolders" && \
    jcheck "enumerateBrowsableFolders — contains '$SF_NAME'" "$OUT" \
        'any(.[]; .uuid == $u)' --arg u "$SF_UUID"
assert_rpc "enumerateUsers — contains root" "FileManager" "enumerateUsers" '{}' \
    '"name":"root"' >/dev/null
assert_rpc "enumerateGroups — contains users" "FileManager" "enumerateGroups" '{}' \
    '"name":"users"' >/dev/null

# ===========================================================================
section "Create"
# ===========================================================================

assert_rpc "mkDir — test folder" "FileManager" "mkDir" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"root\",\"name\":\"$TEST_NAME\"}" >/dev/null
TEST_DIR="$SF_PATH/$TEST_NAME"
if [ ! -d "$TEST_DIR" ]; then
    echo -e "\n${RED}Test folder was not created — aborting.${NC}" >&2
    exit 1
fi
T="$TEST_NAME"   # relative path of the test folder
check "mkDir — inherits owner/group of the parent" \
    test "$(stat -c %u:%g "$TEST_DIR")" = "$(stat -c %u:%g "$SF_PATH")"

# Give the test folder a known owner and mode so inheritance is visible.
chown nobody:users "$TEST_DIR"
chmod 2775 "$TEST_DIR"

assert_rpc "mkDir — subfolder" "FileManager" "mkDir" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"sub\"}" >/dev/null
check "mkDir — subfolder is nobody:users 2775" \
    test "$(stat -c '%U:%G %a' "$TEST_DIR/sub")" = "nobody:users 2775"
assert_rpc "mkFile" "FileManager" "mkFile" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"a.txt\"}" >/dev/null
check "mkFile — is nobody:users 664" \
    test "$(stat -c '%U:%G %a' "$TEST_DIR/a.txt")" = "nobody:users 664"
assert_rpc_fails "mkFile — existing name rejected" "FileManager" "mkFile" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"a.txt\"}" "already exists"
assert_rpc_fails "mkDir — name with slash rejected" "FileManager" "mkDir" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"x/y\"}" "invalid name"
assert_rpc_fails "mkDir — '..' rejected" "FileManager" "mkDir" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"..\"}" "invalid name"
assert_rpc_fails "mkFile — name with newline rejected" "FileManager" "mkFile" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"x\\ny\"}" "invalid name"

# Fixture files created directly.
printf 'hello\n' > "$TEST_DIR/sub/foo.log"
printf 'ab\0cd' > "$TEST_DIR/bin.dat"
printf 'caf\xe9' > "$TEST_DIR/latin1.txt"
printf '<script>alert(1)</script>' > "$TEST_DIR/page.html"
printf '.' > "$TEST_DIR/.hidden"
head -c $((1024 * 1024 + 1)) /dev/zero | tr '\0' 'x' > "$TEST_DIR/big.txt"
echo "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==" \
    | base64 -d > "$TEST_DIR/pic.png"
OUTSIDE_DIR=$(mktemp -d /tmp/fm-rpctest-outside.XXXXXX)
ln -s "$OUTSIDE_DIR" "$TEST_DIR/escape"
ln -s sub "$TEST_DIR/sublink"
ln -s missing "$TEST_DIR/broken"

# ===========================================================================
section "Listing & confinement"
# ===========================================================================

assert_rpc "getList — test folder" "FileManager" "getList" "$(list_params "$T")" && {
    jcheck "getList — '..' row present" "$OUT" \
        'any(.data[]; .type == "parentdir")'
    jcheck "getList — hidden file shown" "$OUT" \
        'any(.data[]; .name == ".hidden")'
    check "getList — broken link typed 'brokenlink'" \
        test "$(echo "$OUT" | jq -r '.data[] | select(.name == "broken") | .type')" = "brokenlink"
    check "getList — symlink to folder is 'dir' with target" \
        test "$(echo "$OUT" | jq -r '.data[] | select(.name == "sublink") | "\(.type) \(.link)"')" = "dir sub"
    check "getList — a.txt editable, big.txt not" \
        test "$(echo "$OUT" | jq -r '[.data[] | select(.name == "a.txt" or .name == "big.txt") | .editable] | join(",")')" = "true,false"
    check "getList — pic.png previewable as image" \
        test "$(echo "$OUT" | jq -r '.data[] | select(.name == "pic.png") | .preview')" = "image"
    check "getList — dirpath is the listed folder" \
        test "$(echo "$OUT" | jq -r '.data[] | select(.name == "a.txt") | .dirpath')" = "$(tok "$T")"
    jcheck "getList — no 'parent' key (tree relation is set client-side)" "$OUT" \
        'all(.data[]; has("parent") | not)'
    jcheck "getList — rows carry the shared folder" "$OUT" \
        'all(.data[]; .uuid == $u)' --arg u "$SF_UUID"
    jcheck "getList — folder links use the alternate route" "$OUT" \
        'all(.data[]; .route == "open")'
}
assert_rpc "getList — from the alternate route" "FileManager" "getList" \
    "$(list_params "$T" | jq -c '. + {altroute: "true"}')" && \
    jcheck "getList — folder links use the default route" "$OUT" \
        'all(.data[]; .route == "browse")'
assert_rpc "getList — top level" "FileManager" "getList" "$(list_params "")" && \
    jcheck "getList — top-level '..' leads to the shared folders" "$OUT" \
        'any(.data[]; .type == "parentdir" and .path == "")'

assert_rpc "getLocation" "FileManager" "getLocation" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/sub")\"}" \
    "\"location\":\"/$T/sub\"" >/dev/null
assert_rpc_fails "getList — symlink escaping the shared folder" "FileManager" "getList" \
    "$(list_params "$T/escape")" "escapes"
assert_rpc_fails "getList — two-dot path" "FileManager" "getList" \
    "$(list_params "$T/../..")" "two-dot"
assert_rpc_fails "getList — invalid token" "FileManager" "getList" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"!!!\",\"start\":0,\"limit\":null}"
set_settings '.showhidden = false'
OUT=$(rpc "FileManager" "getList" "$(list_params "$T")" 2>/dev/null || echo '{"data":[]}')
jcheck "getList — hidden file filtered with showhidden off" "$OUT" \
    '(any(.data[]; .name == ".hidden")) | not'
set_settings '.'

# ===========================================================================
section "Rename"
# ===========================================================================

assert_rpc "rename — symlink" "FileManager" "rename" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/sublink")\",\"name\":\"sublink2\"}" >/dev/null
check "rename — renamed the link, target untouched" \
    bash -c "[ -L '$TEST_DIR/sublink2' ] && [ -d '$TEST_DIR/sub' ]"
assert_rpc_fails "rename — onto existing name" "FileManager" "rename" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\",\"name\":\"bin.dat\"}" "already exists"
assert_rpc_fails "rename — shared folder root" "FileManager" "rename" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"root\",\"name\":\"x\"}"

# ===========================================================================
section "Editor"
# ===========================================================================

chmod 640 "$TEST_DIR/a.txt"
setfacl -m u:root:rw "$TEST_DIR/a.txt" 2>/dev/null && HAVE_ACL=true || HAVE_ACL=false
INODE=$(stat -c %i "$TEST_DIR/a.txt")
assert_rpc "setFileContent" "FileManager" "setFileContent" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\",\"content\":\"changed\\n\"}" >/dev/null
check "setFileContent — content written" \
    test "$(cat "$TEST_DIR/a.txt")" = "changed"
check "setFileContent — replaced atomically (new inode)" \
    test "$(stat -c %i "$TEST_DIR/a.txt")" != "$INODE"
check "setFileContent — owner kept" \
    test "$(stat -c '%U:%G' "$TEST_DIR/a.txt")" = "nobody:users"
if $HAVE_ACL; then
    check "setFileContent — ACL kept" \
        bash -c "getfacl -p '$TEST_DIR/a.txt' 2>/dev/null | grep -q '^user:root:rw-'"
else
    info "ACLs not supported on this file system — ACL check skipped"
fi
check "setFileContent — no temporary file left" \
    bash -c "! ls -A '$TEST_DIR' | grep -q '^\.a\.txt\.'"
ln "$TEST_DIR/a.txt" "$TEST_DIR/hard.txt"
assert_rpc "setFileContent — file with hard links" "FileManager" "setFileContent" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\",\"content\":\"linked\"}" >/dev/null
check "setFileContent — hard link kept" \
    test "$(cat "$TEST_DIR/hard.txt")" = "linked"
rm -f "$TEST_DIR/hard.txt"
assert_rpc "getFileContent" "FileManager" "getFileContent" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\"}" '"content":"linked"' && {
    ETAG=$(echo "$OUT" | jq -r '.etag')
    check "getFileContent — etag is the SHA-1 of the content" \
        test "$ETAG" = "$(sha1sum < "$TEST_DIR/a.txt" | cut -d' ' -f1)"
    printf 'external' > "$TEST_DIR/a.txt"
    assert_rpc_fails "setFileContent — refused if changed since opened" "FileManager" \
        "setFileContent" "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\",\"content\":\"mine\",\"etag\":\"$ETAG\"}" \
        "changed by someone else"
    check "setFileContent — concurrent change kept" \
        test "$(cat "$TEST_DIR/a.txt")" = "external"
    assert_rpc "setFileContent — current etag" "FileManager" "setFileContent" \
        "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\",\"content\":\"mine\",\"etag\":\"$(printf 'external' | sha1sum | cut -d' ' -f1)\"}" >/dev/null
    check "setFileContent — saved with current etag" \
        test "$(cat "$TEST_DIR/a.txt")" = "mine"
}
assert_rpc_fails "getFileContent — binary file" "FileManager" "getFileContent" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/bin.dat")\"}" "binary"
assert_rpc_fails "getFileContent — non-UTF-8 file" "FileManager" "getFileContent" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/latin1.txt")\"}" "UTF-8"
assert_rpc_fails "getFileContent — larger than the limit" "FileManager" "getFileContent" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/big.txt")\"}" "larger"

# ===========================================================================
section "Search"
# ===========================================================================

printf 'x' > "$TEST_DIR/sub/FooBar.TXT"
assert_rpc "search — 'foo'" "FileManager" "search" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"query\":\"foo\",\"start\":0,\"limit\":null,\"sortfield\":\"name\",\"sortdir\":\"asc\"}" && {
    check "search — case-insensitive, recursive" \
        test "$(echo "$OUT" | names | sort | tr '\n' ',')" = "FooBar.TXT,foo.log,"
    check "search — location of a result" \
        test "$(echo "$OUT" | jq -r '.data[] | select(.name == "foo.log") | .location')" = "/$T/sub"
}
assert_rpc "search — wildcard '*.log'" "FileManager" "search" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"query\":\"*.log\",\"start\":0,\"limit\":null}" && \
    check "search — wildcard result" test "$(echo "$OUT" | names)" = "foo.log"
# Names created otherwise (e.g. via SMB) may contain newlines and blanks.
ODD="odd "$'\n'"name.txt"
printf 'x' > "$TEST_DIR/sub/$ODD"
assert_rpc "search — name with newline and blank" "FileManager" "search" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"query\":\"odd\",\"start\":0,\"limit\":null}" && \
    jcheck "search — name with newline and blank found intact" "$OUT" \
        'any(.data[]; .name == $n)' --arg n "$ODD"
rm -f -- "$TEST_DIR/sub/$ODD"

# ===========================================================================
section "Copy & move"
# ===========================================================================

assert_rpc "mkDir — destination" "FileManager" "mkDir" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"dest\"}" >/dev/null
assert_bg "transfer — copy two items" "transfer" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/sub"),$(tok "$T/pic.png")\",\"destuuid\":\"$SF_UUID\",\"destpath\":\"$T/dest/\",\"mode\":\"copy\",\"overwrite\":false}" \
    ok >/dev/null
check "transfer — copies exist, sources kept" \
    bash -c "[ -f '$TEST_DIR/dest/sub/foo.log' ] && [ -f '$TEST_DIR/dest/pic.png' ] && [ -f '$TEST_DIR/pic.png' ]"
assert_bg "transfer — no overwrite by default" "transfer" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/pic.png")\",\"destuuid\":\"$SF_UUID\",\"destpath\":\"$T/dest\",\"mode\":\"copy\",\"overwrite\":\"false\"}" \
    fail "already exists" >/dev/null
assert_bg "transfer — move into itself refused" "transfer" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/dest")\",\"destuuid\":\"$SF_UUID\",\"destpath\":\"$T/dest/sub\",\"mode\":\"move\",\"overwrite\":false}" \
    fail "into itself" >/dev/null
assert_bg "transfer — move" "transfer" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/dest/pic.png")\",\"destuuid\":\"$SF_UUID\",\"destpath\":\"$T/sub\",\"mode\":\"move\",\"overwrite\":false}" \
    ok >/dev/null
check "transfer — moved" \
    bash -c "[ -f '$TEST_DIR/sub/pic.png' ] && [ ! -e '$TEST_DIR/dest/pic.png' ]"
assert_rpc_fails "transfer — destination outside the shared folder" "FileManager" "transfer" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"destuuid\":\"$SF_UUID\",\"destpath\":\"$T/escape\",\"mode\":\"copy\",\"overwrite\":false}" \
    "escapes"

# ===========================================================================
section "Duplicate & symbolic links"
# ===========================================================================

assert_bg "duplicate — file and folder" "duplicate" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/pic.png"),$(tok "$T/dest")\"}" ok >/dev/null
check "duplicate — 'pic (copy).png' and 'dest (copy)' created" \
    bash -c "[ -f '$TEST_DIR/pic (copy).png' ] && [ -d '$TEST_DIR/dest (copy)/sub' ]"
check "duplicate — content identical" \
    cmp -s "$TEST_DIR/pic.png" "$TEST_DIR/pic (copy).png"
assert_bg "duplicate — again numbers the copy" "duplicate" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/pic.png")\"}" ok >/dev/null
check "duplicate — 'pic (copy 2).png' created" test -f "$TEST_DIR/pic (copy 2).png"
assert_bg "duplicate — symlink copied as link" "duplicate" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/escape")\"}" ok >/dev/null
check "duplicate — link not dereferenced" \
    bash -c "[ -L '$TEST_DIR/escape (copy)' ] && [ \"\$(readlink '$TEST_DIR/escape (copy)')\" = '$OUTSIDE_DIR' ]"
rm -f "$TEST_DIR/escape (copy)"
assert_rpc_fails "duplicate — shared folder root refused" "FileManager" "duplicate" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"root\"}"
rm -rf "$TEST_DIR/pic (copy).png" "$TEST_DIR/pic (copy 2).png" "$TEST_DIR/dest (copy)"

mklink() {  # $1 target, $2 destination folder, $3 name
    echo "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$1")\",\"destpath\":\"$2\",\"name\":\"$3\"}"
}
assert_rpc "mkLink — link to a file in another folder" "FileManager" "mkLink" \
    "$(mklink "$T/sub/foo.log" "$T/dest" "foo-link.log")" >/dev/null
check "mkLink — relative link target" \
    test "$(readlink "$TEST_DIR/dest/foo-link.log")" = "../sub/foo.log"
check "mkLink — link resolves to the file" \
    test "$(cat "$TEST_DIR/dest/foo-link.log")" = "hello"
check "mkLink — link owned like the folder" \
    test "$(stat -c '%U:%G' "$TEST_DIR/dest/foo-link.log")" = "nobody:users"
assert_rpc "mkLink — link to a folder at the top level" "FileManager" "mkLink" \
    "$(mklink "$T/sub" "" "$TEST_NAME-sublink")" >/dev/null
check "mkLink — top level link target" \
    test "$(readlink "$SF_PATH/$TEST_NAME-sublink")" = "$T/sub"
rm -f "$SF_PATH/$TEST_NAME-sublink"
assert_rpc_fails "mkLink — existing name" "FileManager" "mkLink" \
    "$(mklink "$T/sub/foo.log" "$T/dest" "foo-link.log")" "already exists"
assert_rpc_fails "mkLink — target outside the shared folder" "FileManager" "mkLink" \
    "$(mklink "$T/escape" "$T/dest" "out")" "escapes"
assert_rpc_fails "mkLink — destination outside the shared folder" "FileManager" "mkLink" \
    "$(mklink "$T/a.txt" "$T/escape" "out")" "escapes"
assert_rpc_fails "mkLink — missing target" "FileManager" "mkLink" \
    "$(mklink "$T/nope" "$T/dest" "x")"
assert_rpc_fails "mkLink — invalid name" "FileManager" "mkLink" \
    "$(mklink "$T/a.txt" "$T/dest" "../x")" "invalid name"
check "mkLink — nothing created outside" test ! -e "$OUTSIDE_DIR/out"

# ===========================================================================
section "Archives"
# ===========================================================================

assert_bg "compress — zip" "compress" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/sub"),$(tok "$T/a.txt")\",\"name\":\"arch\",\"format\":\"zip\"}" \
    ok "Created 'arch.zip'" >/dev/null
check "compress — arch.zip exists" test -f "$TEST_DIR/arch.zip"
assert_bg "compress — tar.gz" "compress" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/sub")\",\"name\":\"arch.tar.gz\",\"format\":\"tar.gz\"}" \
    ok "Created 'arch.tar.gz'" >/dev/null
assert_rpc_fails "compress — existing archive name" "FileManager" "compress" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/sub")\",\"name\":\"arch\",\"format\":\"zip\"}" \
    "already exists"
assert_rpc_fails "compress — items from different folders" "FileManager" "compress" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt"),$(tok "$T/sub/foo.log")\",\"name\":\"x\",\"format\":\"zip\"}" \
    "same folder"
assert_bg "extract — zip" "extract" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/arch.zip")\"}" ok >/dev/null
check "extract — zip contents in 'arch/'" \
    bash -c "[ -f '$TEST_DIR/arch/sub/foo.log' ] && [ -f '$TEST_DIR/arch/a.txt' ]"
check "extract — extracted files owned like the parent" \
    test "$(stat -c '%U:%G' "$TEST_DIR/arch/sub/foo.log")" = "nobody:users"
assert_bg "extract — tar.gz into a new folder" "extract" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/arch.tar.gz")\"}" ok "arch (2)" >/dev/null
check "extract — tar.gz contents" test -f "$TEST_DIR/arch (2)/sub/foo.log"
python3 - "$TEST_DIR/evil.zip" <<'EOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("../../fm-rpctest-zipslip", "x")
    z.writestr("/tmp/fm-rpctest-zipslip-abs", "x")
EOF
assert_bg "extract — malicious zip" "extract" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/evil.zip")\"}" ok >/dev/null
check "extract — zip slip contained" \
    bash -c "[ ! -e '$SF_PATH/../fm-rpctest-zipslip' ] && [ ! -e '$SF_PATH/fm-rpctest-zipslip' ] && [ ! -e /tmp/fm-rpctest-zipslip-abs ]"
assert_rpc_fails "extract — not an archive" "FileManager" "extract" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\"}" "not a supported archive"
if command -v bsdtar &>/dev/null; then
    (cd "$TEST_DIR" && bsdtar --format 7zip -cf seven.7z sub && \
        bsdtar --format iso9660 -cf disc.iso sub) 2>/dev/null
    assert_bg "extract — 7z" "extract" \
        "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/seven.7z")\"}" ok "Extracted to 'seven'" >/dev/null
    check "extract — 7z contents" test "$(cat "$TEST_DIR/seven/sub/foo.log")" = "hello"
    check "extract — 7z contents owned like the parent" \
        test "$(stat -c '%U:%G' "$TEST_DIR/seven/sub/foo.log")" = "nobody:users"
    assert_bg "extract — ISO" "extract" \
        "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/disc.iso")\"}" ok >/dev/null
    check "extract — ISO contents" \
        bash -c "cat '$TEST_DIR/disc/'[sS][uU][bB]/[fF][oO][oO].[lL][oO][gG]* | grep -q hello"
    # A 7z archive with a member escaping the target folder.
    printf 'x' > "$TEST_DIR/slip.txt"
    (cd "$TEST_DIR" && bsdtar --format 7zip -P -s ',^slip.txt$,../../fm-rpctest-7zslip,' \
        -cf slip.7z slip.txt) 2>/dev/null
    if bsdtar -tf "$TEST_DIR/slip.7z" 2>/dev/null | grep -q '^\.\./'; then
        assert_bg "extract — malicious 7z refused" "extract" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/slip.7z")\"}" fail >/dev/null
        check "extract — 7z slip contained" \
            bash -c "[ ! -e '$SF_PATH/fm-rpctest-7zslip' ] && [ ! -e '$TEST_DIR/../fm-rpctest-7zslip' ]"
    else
        info "Could not create a malicious 7z archive — 7z slip check skipped"
    fi
    rm -f "$TEST_DIR/slip.txt"
    OUT=$(rpc "FileManager" "getList" "$(list_params "$T")" 2>/dev/null || echo '{"data":[]}')
    check "getList — 7z and ISO marked as archives" \
        test "$(echo "$OUT" | jq -r '[.data[] | select(.name == "seven.7z" or .name == "disc.iso") | .archive] | join(",")')" = "true,true"
else
    info "bsdtar not installed — 7z/ISO extraction skipped"
fi

# ===========================================================================
section "Symlinks out of the shared folder"
# ===========================================================================

# Such links can be created by users, e.g. by extracting a tar archive.
printf 'secret' > "$OUTSIDE_DIR/secret"
printf 'original' > "$OUTSIDE_DIR/victim"
ln -s "$OUTSIDE_DIR/secret" "$TEST_DIR/leak"
ln -s "$OUTSIDE_DIR/victim" "$TEST_DIR/trap.tar.gz.fmpart"
ln -s "$OUTSIDE_DIR/created" "$TEST_DIR/dangling"
assert_rpc_fails "compress — symlink not added to a ZIP" "FileManager" "compress" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/leak")\",\"name\":\"leak\",\"format\":\"zip\"}" \
    "symbolic link"
check "compress — no ZIP with the link target created" test ! -e "$TEST_DIR/leak.zip"
assert_bg "compress — tar.gz stores a symlink as link" "compress" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/leak")\",\"name\":\"leak\",\"format\":\"tar.gz\"}" \
    ok >/dev/null
check "compress — tar.gz contains the link, not the target" \
    bash -c "tar -tvzf '$TEST_DIR/leak.tar.gz' | grep -q '^l'"
assert_rpc_fails "compress — planted partial archive refused" "FileManager" "compress" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"name\":\"trap\",\"format\":\"tar.gz\"}" \
    "already exists"
check "compress — link target of the partial archive untouched" \
    test "$(cat "$OUTSIDE_DIR/victim")" = "original"
PROPS=$(mktemp)
STAGED+=("$PROPS")
assert_bg "getProperties — symlink out of the shared folder" "getProperties" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/leak")\"}" ok "Link target:" > "$PROPS"
check "getProperties — link target not inspected" \
    bash -c "! grep -q '^MIME type:' '$PROPS'"
assert_rpc "delete — dangling symlink to trash" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/dangling")\"}" >/dev/null
check "delete — link target not created by the trash" \
    test ! -e "$OUTSIDE_DIR/created"
rm -f "$TEST_DIR/trap.tar.gz.fmpart"

# ===========================================================================
section "Permissions & properties"
# ===========================================================================

chmod 644 "$TEST_DIR/arch/sub/foo.log"
assert_bg "chmod — recursive 2770" "chmod" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/arch")\",\"mode\":\"2770\",\"recursive\":\"true\"}" \
    ok >/dev/null
check "chmod — folders 2770" test "$(stat -c %a "$TEST_DIR/arch/sub")" = "2770"
check "chmod — files 660 (no execute bit added)" \
    test "$(stat -c %a "$TEST_DIR/arch/sub/foo.log")" = "660"
assert_rpc_fails "chmod — invalid mode" "FileManager" "chmod" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"mode\":\"999\",\"recursive\":false}"
mkdir "$TEST_DIR/immut"
printf 'x' > "$TEST_DIR/immut/f"
if chattr +i "$TEST_DIR/immut/f" 2>/dev/null; then
    IMMUTABLE="$TEST_DIR/immut/f"
    assert_bg "chmod — recursive failure reported" "chmod" \
        "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/immut")\",\"mode\":\"0770\",\"recursive\":true}" \
        fail "Failed to change the mode" >/dev/null
    chattr -i "$IMMUTABLE"
    IMMUTABLE=""
else
    info "chattr +i not supported on this file system — chmod failure check skipped"
fi
rm -rf "$TEST_DIR/immut"
assert_bg "chown — root:users" "chown" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"owner\":\"root\",\"group\":\"users\",\"recursive\":false}" \
    ok >/dev/null
check "chown — applied" test "$(stat -c '%U:%G' "$TEST_DIR/a.txt")" = "root:users"
assert_rpc_fails "chown — unknown user" "FileManager" "chown" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"owner\":\"no-such-user-$$\",\"group\":\"users\",\"recursive\":false}" \
    "does not exist"
assert_bg "getProperties — folder" "getProperties" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/sub")\"}" ok "Contents:" >/dev/null
assert_bg "getProperties — symlink" "getProperties" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/broken")\"}" ok "(broken)" >/dev/null

# ===========================================================================
section "Checksums"
# ===========================================================================

assert_bg "checksum — SHA-256 of two files" "checksum" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/pic.png"),$(tok "$T/a.txt")\",\"algorithm\":\"sha256\"}" \
    ok "$(sha256sum < "$TEST_DIR/pic.png" | cut -d' ' -f1)  $T/pic.png" >/dev/null
assert_bg "checksum — MD5" "checksum" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"algorithm\":\"md5\"}" \
    ok "$(md5sum < "$TEST_DIR/a.txt" | cut -d' ' -f1)  $T/a.txt" >/dev/null
assert_rpc_fails "checksum — folder refused" "FileManager" "checksum" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/sub")\",\"algorithm\":\"sha256\"}" "not a file"
assert_rpc_fails "checksum — unknown algorithm rejected" "FileManager" "checksum" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"algorithm\":\"crc32\"}"
assert_rpc_fails "checksum — symlink escaping the shared folder" "FileManager" "checksum" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/leak")\",\"algorithm\":\"sha256\"}" "escapes"

# ===========================================================================
section "Disk usage"
# ===========================================================================

# Larger than big.txt (1 MiB), the largest item so far.
head -c 3000000 /dev/zero > "$TEST_DIR/sub/large.bin"
USAGE=$(mktemp)
STAGED+=("$USAGE")
assert_bg "diskUsage — test folder" "diskUsage" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\"}" ok "Total:" > "$USAGE"
check "diskUsage — largest item (sub/ with 3 MB) first" \
    bash -c "grep -E '%  [#.]{20}  ' '$USAGE' | head -1 | grep -qE '  sub/\$'"
check "diskUsage — folders marked with a slash" grep -qE '  sub/$' "$USAGE"
check "diskUsage — files listed" grep -qE '  pic\.png$' "$USAGE"
check "diskUsage — partial uploads not listed" bash -c "! grep -q fmpart '$USAGE'"
check "diskUsage — symlinks not followed" bash -c "! grep -qE '  escape/' '$USAGE'"
assert_rpc_fails "diskUsage — file refused" "FileManager" "diskUsage" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\"}" "not a folder"
assert_rpc_fails "diskUsage — symlink escaping the shared folder" "FileManager" "diskUsage" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/escape")\"}" "escapes"
rm -f "$TEST_DIR/sub/large.bin"

# ===========================================================================
section "Download & preview"
# ===========================================================================

# download.php normally streams and unlinks staged files; remember them.
stage() { local f; f=$(echo "$1" | jq -r 'select(.unlink == true) | .filepath'); [ -n "$f" ] && STAGED+=("$f"); }

assert_rpc "download — file" "FileManager" "download" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/pic.png")\"}" '"filename":"pic.png"' && stage "$OUT"
chmod 600 "$TEST_DIR/latin1.txt"
assert_rpc "download — private file is staged" "FileManager" "download" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/latin1.txt")\"}" '"unlink":true' && {
    stage "$OUT"
    F=$(echo "$OUT" | jq -r '.filepath')
    check "download — staged copy readable by $WEBGUI_USER" \
        test "$(stat -c %U "$F")" = "$WEBGUI_USER"
}
assert_rpc "download — folder as ZIP" "FileManager" "download" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/sub")\"}" '"filename":"sub.zip"' && {
    stage "$OUT"
    check "download — ZIP contains sub/foo.log" \
        python3 -c "import sys,zipfile; sys.exit('sub/foo.log' not in zipfile.ZipFile('$(echo "$OUT" | jq -r .filepath)').namelist())"
}
assert_rpc "downloadArchive — two items" "FileManager" "downloadArchive" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt"),$(tok "$T/sub")\"}" '"filename":"download.zip"' && stage "$OUT"
assert_rpc_fails "downloadArchive — escaping symlink" "FileManager" "downloadArchive" \
    "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/escape")\"}" "escapes"
assert_rpc "preview — image inline" "FileManager" "preview" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/pic.png")\"}" '"Content-Type":"image/png"' && stage "$OUT"
assert_rpc "preview — HTML sent as text/plain" "FileManager" "preview" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/page.html")\"}" 'text/plain' && {
    stage "$OUT"
    jcheck "preview — content sniffing disabled" "$OUT" \
        '.headers["X-Content-Type-Options"] == "nosniff"'
    jcheck "preview — document sandboxed" "$OUT" \
        '.headers["Content-Security-Policy"] == "sandbox"'
}
printf '%%PDF-1.4\n%%%%EOF\n' > "$TEST_DIR/doc.pdf"
assert_rpc "preview — PDF inline" "FileManager" "preview" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/doc.pdf")\"}" '"Content-Type":"application/pdf"' && {
    stage "$OUT"
    jcheck "preview — PDF not sandboxed (breaks the browser viewer)" "$OUT" \
        '(.headers | has("Content-Security-Policy") | not) and .headers["X-Content-Type-Options"] == "nosniff"'
}
assert_rpc "preview — binary file sent as attachment" "FileManager" "preview" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/bin.dat")\"}" '"Content-Disposition":"attachment' && stage "$OUT"

# ===========================================================================
section "Upload"
# ===========================================================================

C1=$(make_chunk "hello ")
C2=$(make_chunk "world")
up() {  # $1 offset, $2 final, $3 overwrite, $4 chunk file, [$5 name]
    echo "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"${5:-up.txt}\",\"offset\":$1,\"final\":$2,\"overwrite\":$3,\"filepath\":\"$4\"}"
}
assert_rpc_fails "uploadChunk — arbitrary file refused" "FileManager" "uploadChunk" \
    "$(up 0 true false /etc/passwd)" "invalid upload chunk"
assert_rpc "uploadChunk — first chunk" "FileManager" "uploadChunk" \
    "$(up 0 false false "$C1")" '"size":6' >/dev/null
OUT=$(rpc "FileManager" "getList" "$(list_params "$T")" 2>/dev/null || echo '{"data":[]}')
jcheck "uploadChunk — partial file hidden from listing" "$OUT" \
    '(any(.data[]; .name | endswith(".fmpart"))) | not'
assert_rpc_fails "uploadChunk — out-of-order chunk" "FileManager" "uploadChunk" \
    "$(up 3 true false "$C2")" "out of sync"
assert_rpc "uploadChunk — last chunk" "FileManager" "uploadChunk" \
    "$(up 6 true false "$C2")" '"size":11' >/dev/null
check "uploadChunk — file assembled" test "$(cat "$TEST_DIR/up.txt")" = "hello world"
check "uploadChunk — owned like the parent" \
    test "$(stat -c '%U:%G' "$TEST_DIR/up.txt")" = "nobody:users"
assert_rpc_fails "uploadChunk — existing file kept" "FileManager" "uploadChunk" \
    "$(up 0 true false "$C1")" "already exists"
assert_rpc "uploadChunk — overwrite" "FileManager" "uploadChunk" \
    "$(up 0 true true "$C1")" >/dev/null
check "uploadChunk — overwritten" test "$(cat "$TEST_DIR/up.txt")" = "hello "
printf 'original' > "$OUTSIDE_DIR/victim2"
ln -s "$OUTSIDE_DIR/victim2" "$TEST_DIR/.up2.txt.fmpart"
printf 'x' > "$TEST_DIR/.stale.bin.fmpart"
touch -d '2 days ago' "$TEST_DIR/.stale.bin.fmpart"
printf 'x' > "$TEST_DIR/.fresh.bin.fmpart"
assert_rpc "uploadChunk — planted partial file" "FileManager" "uploadChunk" \
    "$(up 0 true false "$C1" up2.txt)" >/dev/null
check "uploadChunk — symlink at the partial file name not followed" \
    bash -c "[ \"\$(cat '$OUTSIDE_DIR/victim2')\" = original ] && [ \"\$(cat '$TEST_DIR/up2.txt')\" = 'hello ' ]"
check "uploadChunk — abandoned partial file removed" \
    test ! -e "$TEST_DIR/.stale.bin.fmpart"
check "uploadChunk — recent partial file kept" \
    test -e "$TEST_DIR/.fresh.bin.fmpart"
rm -f "$TEST_DIR/.fresh.bin.fmpart"

# ===========================================================================
section "Download from URL"
# ===========================================================================

durl() {  # $1 URL, [$2 name]
    echo "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"url\":\"$1\",\"name\":\"${2:-}\",\"overwrite\":false}"
}
assert_rpc_fails "downloadUrl — ftp:// refused" "FileManager" "downloadUrl" \
    "$(durl "ftp://example.com/x")" "only http"
assert_rpc_fails "downloadUrl — file:// refused" "FileManager" "downloadUrl" \
    "$(durl "file:///etc/passwd")" "only http"
for u in "http://127.0.0.1/" "http://localhost/" "http://[::1]/" \
    "http://169.254.169.254/" "http://192.168.1.1/" "http://[::ffff:10.0.0.1]/" \
    "http://$(hostname)/"; do
    assert_rpc_fails "downloadUrl — $u refused" "FileManager" "downloadUrl" \
        "$(durl "$u")" "not allowed"
done
assert_rpc_fails "downloadUrl — numeric host refused" "FileManager" "downloadUrl" \
    "$(durl "http://2130706433/")" "invalid host"
assert_rpc_fails "downloadUrl — invalid file name" "FileManager" "downloadUrl" \
    "$(durl "https://example.com/" "../x")" "invalid name"
if curl -sf -o /dev/null --max-time 10 https://example.com/; then
    assert_bg "downloadUrl — download" "downloadUrl" \
        "$(durl "https://example.com/" "example.html")" ok "Saved 'example.html'" >/dev/null
    check "downloadUrl — file stored" grep -qi "example domain" "$TEST_DIR/example.html"
    check "downloadUrl — owned like the parent" \
        test "$(stat -c '%U:%G' "$TEST_DIR/example.html")" = "nobody:users"
    assert_bg "downloadUrl — existing name gets a number" "downloadUrl" \
        "$(durl "https://example.com/" "example.html")" ok "Saved 'example (2).html'" >/dev/null
    check "downloadUrl — no partial file left" \
        bash -c "! ls -A '$TEST_DIR' | grep -q '^\.download-.*\.fmpart$'"
else
    info "No internet access, skipping the download tests."
fi

# ===========================================================================
section "Trash"
# ===========================================================================

TR="$SF_PATH/.recycle/admin/$T"
assert_rpc "delete — to trash" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/up.txt")\"}" >/dev/null
check "delete — moved to .recycle/admin/" \
    bash -c "[ ! -e '$TEST_DIR/up.txt' ] && [ -f '$TR/up.txt' ]"
printf 'v2' > "$TEST_DIR/up.txt"
assert_rpc "delete — same name again" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/up.txt")\"}" >/dev/null
check "delete — collision suffix .~2~" test -f "$TR/up.txt.~2~"
OUT=$(rpc "FileManager" "getList" "$(list_params ".recycle/admin/$T")" 2>/dev/null || echo '{"data":[]}')
check "getList — trashed flag in trash" \
    test "$(echo "$OUT" | jq -r '.data[] | select(.name == "up.txt") | .trashed')" = "true"
assert_rpc "restore — strips suffix" "FileManager" "restore" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok ".recycle/admin/$T/up.txt.~2~")\"}" >/dev/null
check "restore — back in place" test "$(cat "$TEST_DIR/up.txt")" = "v2"
assert_rpc_fails "restore — target exists" "FileManager" "restore" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok ".recycle/admin/$T/up.txt")\"}" "already exists"
assert_rpc_fails "restore — item not in trash" "FileManager" "restore" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\"}" "not in the trash"
assert_rpc "delete — symlink" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/sublink2")\"}" >/dev/null
check "delete — only the link was trashed" \
    bash -c "[ -L '$TR/sublink2' ] && [ -d '$TEST_DIR/sub' ]"
assert_rpc "delete — folder to trash" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/arch (2)")\"}" >/dev/null
assert_rpc "getTrashList" "FileManager" "getTrashList" "$GETLIST" && {
    ROW=$(echo "$OUT" | jq -c --arg u "$SF_UUID" --arg l "/$T" \
        '.data[] | select(.uuid == $u and .location == $l and .name == "arch (2)")')
    check "getTrashList — deleted folder listed once, as folder" \
        test "$(echo "$ROW" | jq -r '"\(.type) \(.user) \(.sharename)"')" = "dir admin $SF_NAME"
    jcheck "getTrashList — contents of a deleted folder not listed" "$OUT" \
        '(any(.data[]; .location | startswith($l))) | not' --arg l "/$T/arch (2)"
    jcheck "getTrashList — deleted symlink listed as link" "$OUT" \
        'any(.data[]; .name == "sublink2" and .type == "link")'
    jcheck "getTrashList — item whose original exists again marked as conflict" "$OUT" \
        'any(.data[]; .name == "up.txt" and .location == $l and .conflict == true)' --arg l "/$T"
    jcheck "getTrashList — original folder token" "$OUT" \
        'any(.data[]; .name == "arch (2)" and .origdir == $t)' --arg t "$(tok "$T")"
    check "getTrashList — deletion time is recent" \
        test "$(( $(date +%s) - $(echo "$ROW" | jq -r '.deleted') ))" -lt 600
    assert_rpc "restore — via the trash list" "FileManager" "restore" \
        "{\"uuid\":\"$SF_UUID\",\"path\":\"$(echo "$ROW" | jq -r '.path')\"}" >/dev/null
    check "restore — folder back in place" test -f "$TEST_DIR/arch (2)/sub/foo.log"
}
printf 'x' > "$TEST_DIR/nl"$'\n'"name"
assert_rpc "delete — name with newline" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/nl"$'\n'"name")\"}" >/dev/null
sleep 1
check "audit log — control characters replaced, one line per entry" \
    bash -c "journalctl --quiet --no-pager SYSLOG_IDENTIFIER=omv-filemanager --since '$START_TS' --output=cat | grep -qF '] trash: $SF_NAME:/$T/nl?name'"
assert_rpc "delete — permanently" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/up.txt")\",\"permanent\":true}" >/dev/null
check "delete — permanent delete bypasses the trash" \
    bash -c "[ ! -e '$TEST_DIR/up.txt' ] && [ ! -e '$TR/up.txt.~2~' ]"
set_settings '.usetrash = false'
assert_rpc "delete — trash disabled" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/big.txt")\"}" >/dev/null
check "delete — trash disabled deletes" \
    bash -c "[ ! -e '$TEST_DIR/big.txt' ] && [ ! -e '$TR/big.txt' ]"
set_settings '.'
assert_rpc_fails "delete — shared folder root" "FileManager" "delete" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"root\",\"permanent\":true}"
assert_bg "purgeTrash — disabled by default" "purgeTrash" '{}' ok "disabled" >/dev/null
if ! $TRASH_EXISTED; then
    set_settings '.trashretention = 1'
    assert_bg "purgeTrash — recent items kept" "purgeTrash" \
        "{\"uuid\":\"$SF_UUID\"}" ok "Deleted 0 item" >/dev/null
    check "purgeTrash — trash unchanged" test -L "$TR/sublink2"
    set_settings '.'
    sleep 2
    assert_bg "purgeTrash — all items older than 0 days" "purgeTrash" \
        "{\"uuid\":\"$SF_UUID\",\"days\":0}" ok "Deleted [1-9][0-9]* item" >/dev/null
    check "purgeTrash — items and empty containers removed" \
        bash -c "[ ! -e '$TR' ] && [ -d '$SF_PATH/.recycle/admin' ]"
    OUT=$(rpc "FileManager" "getTrashList" "$GETLIST" 2>/dev/null || echo '{"data":[]}')
    jcheck "getTrashList — empty after purge" "$OUT" \
        '(any(.data[]; .uuid == $u)) | not' --arg u "$SF_UUID"
    assert_rpc "emptyTrash" "FileManager" "emptyTrash" "{\"uuid\":\"$SF_UUID\"}" >/dev/null
    check "emptyTrash — trash is empty" \
        test -z "$(ls -A "$SF_PATH/.recycle" 2>/dev/null)"
else
    info "purgeTrash and emptyTrash skipped — '$SF_PATH/.recycle' existed before the test"
fi
assert_rpc_fails "purgeTrash — negative days rejected" "FileManager" "purgeTrash" \
    '{"days":-1}'

# ===========================================================================
section "Share links"
# ===========================================================================

SHARE_UNIT=openmediavault-filemanager-share.service
SHARE_BASE="http://127.0.0.1:$SHARE_PORT/s"
EXPORT=/var/lib/openmediavault-filemanager/share-export.json
CURL=(curl -s --max-time 20)
mklinkp() {  # $1 path, [$2 password], [$3 max downloads], [$4 days]
    echo "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$1")\",\"expires\":${4:-1},\"password\":\"${2:-}\",\"maxdownloads\":${3:-0}}"
}
# Create a share link and store its token in TOK. Not to be called in a
# command substitution, the token must be recorded for the cleanup.
share() {
    local out
    TOK=""
    out=$(omv-rpc -u "$RPC_USER" "FileManager" "createShareLink" "$(mklinkp "$@")" 2>/dev/null) || return 1
    TOK=$(echo "$out" | jq -r '.token')
    [ -n "$TOK" ] && [ "$TOK" != "null" ] || return 1
    SHARE_TOKENS+=("$TOK")
}
http_status() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@"; }
downloads() {
    omv-rpc -u admin "FileManager" "getShareLinkList" "$GETLIST" 2>/dev/null \
        | jq -r --arg t "$1" '.data[] | select(.token == $t) | "\(.downloads) \(.status)"'
}

assert_rpc_fails "createShareLink — refused while disabled" "FileManager" "createShareLink" \
    "$(mklinkp "$T/pic.png")" "disabled"
check "share server — not running while disabled" \
    bash -c "! systemctl --quiet is-active $SHARE_UNIT"
set_settings '.sharelinks = true'
check "share server — running when enabled" systemctl --quiet is-active "$SHARE_UNIT"
MAIN_PID=$(systemctl show -p MainPID --value "$SHARE_UNIT")
CHILD_PID=$(pgrep -P "$MAIN_PID" | head -1)
check "share server — HTTP process runs as omv-fm-share" \
    test "$(stat -c %U "/proc/$CHILD_PID" 2>/dev/null)" = "omv-fm-share"
check "share server — HTTP process is chrooted to an empty folder" \
    test "$(readlink "/proc/$CHILD_PID/root" 2>/dev/null)" = "/run/openmediavault-filemanager-share/empty"
check "share server — HTTP process has no capabilities" \
    bash -c "grep -E '^Cap(Eff|Prm):' /proc/$CHILD_PID/status | grep -qvE '0{16}' && exit 1 || exit 0"
check "share server — only the HTTP process listens on the port" \
    bash -c "ss -Hltnp 'sport = :$SHARE_PORT' | grep -q 'pid=$CHILD_PID,' && ! ss -Hltnp 'sport = :$SHARE_PORT' | grep -q 'pid=$MAIN_PID,'"
check "share server — broker has no sockets to the network" \
    bash -c "! ss -Htunap | grep -q 'pid=$MAIN_PID,'"
check "share server — export readable by root only" \
    test "$(stat -c '%U %a' "$EXPORT")" = "root 600"

if share "$T/pic.png"; then
    _pass "createShareLink — file"
    OUT=$(omv-rpc -u admin "FileManager" "getShareLinkList" "$GETLIST")
    jcheck "getShareLinkList — link listed" "$OUT" \
        'any(.data[]; .token == $t and .status == "active" and .protected == false and .type == "file" and .name == "pic.png")' --arg t "$TOK"
    jcheck "getShareLinkList — URL with the share port" "$OUT" \
        'any(.data[]; .token == $t and (.url | test(":" + $p + "/s/" + $t + "$")))' --arg t "$TOK" --arg p "$SHARE_PORT"
    check "share export — contains the link" jq -e --arg t "$TOK" '.links[$t].path' "$EXPORT"
    check "share server — landing page" test "$(http_status "$SHARE_BASE/$TOK")" = 200
    DL=$(mktemp); STAGED+=("$DL")
    HDR=$("${CURL[@]}" -D - -o "$DL" "$SHARE_BASE/$TOK?dl=1")
    check "share server — file downloaded" cmp -s "$DL" "$TEST_DIR/pic.png"
    check "share server — sent as attachment" bash -c "echo \"\$0\" | grep -qi '^content-disposition: attachment'" "$HDR"
    check "share server — no referrer" bash -c "echo \"\$0\" | grep -qi '^referrer-policy: no-referrer'" "$HDR"
    check "share server — download counted" test "$(downloads "$TOK")" = "1 active"
    check "share server — unknown link" test "$(http_status "$SHARE_BASE/AAAAAAAAAAAAAAAAAAAAAA")" = 404
    check "share server — nothing else served" test "$(http_status "http://127.0.0.1:$SHARE_PORT/")" = 404
else
    _fail "createShareLink — file"
fi

if share "$T/a.txt" "pw-$$" 1; then
    _pass "createShareLink — with password and download limit"
    JAR=$(mktemp); STAGED+=("$JAR")
    check "share server — password required" test "$(http_status "$SHARE_BASE/$TOK?dl=1")" = 401
    check "share server — wrong password" \
        test "$(http_status -d "password=wrong" "$SHARE_BASE/$TOK")" = 401
    check "share server — right password" \
        test "$(http_status -c "$JAR" -d "password=pw-$$" "$SHARE_BASE/$TOK")" = 303
    check "share server — download with session" \
        test "$("${CURL[@]}" -b "$JAR" "$SHARE_BASE/$TOK?dl=1")" = "$(cat "$TEST_DIR/a.txt")"
    check "share server — download limit reached" \
        test "$(http_status -b "$JAR" "$SHARE_BASE/$TOK?dl=1")" = 410
    check "getShareLinkList — link used up" test "$(downloads "$TOK")" = "1 exhausted"
    check "share export — password stored hashed" \
        jq -e --arg t "$TOK" '.links[$t].password | startswith("pbkdf2_sha256$")' "$EXPORT"
    check "share links — password not stored in plain text" \
        bash -c "! grep -qF 'pw-$$' '$EXPORT' /var/lib/openmediavault-filemanager/sharelinks.json"
else
    _fail "createShareLink — with password and download limit"
fi

if share "$T/sub"; then
    _pass "createShareLink — folder"
    check "share server — folder redirects to a trailing slash" \
        test "$(http_status "$SHARE_BASE/$TOK")" = 301
    check "share server — folder listing" \
        bash -c "${CURL[*]} '$SHARE_BASE/$TOK/' | grep -q 'foo.log'"
    check "share server — file in folder" \
        test "$("${CURL[@]}" "$SHARE_BASE/$TOK/foo.log?dl=1")" = "hello"
    ZIPF=$(mktemp); STAGED+=("$ZIPF")
    "${CURL[@]}" -o "$ZIPF" "$SHARE_BASE/$TOK/?zip=1"
    check "share server — folder as ZIP" \
        python3 -c "import sys,zipfile; sys.exit('sub/foo.log' not in zipfile.ZipFile('$ZIPF').namelist())"
    for p in "..%2Fa.txt" "../a.txt" "%2E%2E/a.txt"; do
        check "share server — traversal '$p' refused" \
            bash -c "[ \"\$(${CURL[*]} -o /dev/null -w '%{http_code}' --path-as-is '$SHARE_BASE/$TOK/$p?dl=1')\" != 200 ]"
    done
    ln -s "$OUTSIDE_DIR/secret" "$TEST_DIR/sub/leak2"
    check "share server — symlink in a shared folder not followed" \
        test "$(http_status "$SHARE_BASE/$TOK/leak2?dl=1")" = 404
    rm -f "$TEST_DIR/sub/leak2"
else
    _fail "createShareLink — folder"
fi

assert_rpc_fails "createShareLink — symlink escaping the shared folder" "FileManager" \
    "createShareLink" "$(mklinkp "$T/escape")" "escapes"
mkdir -p "$SF_PATH/.recycle/admin"
printf 'x' > "$SF_PATH/.recycle/admin/$TEST_NAME-trashed"
assert_rpc_fails "createShareLink — item in the trash" "FileManager" "createShareLink" \
    "$(mklinkp ".recycle/admin/$TEST_NAME-trashed")" "trash"
rm -f "$SF_PATH/.recycle/admin/$TEST_NAME-trashed"
assert_rpc_fails "createShareLink — negative expiry rejected" "FileManager" "createShareLink" \
    "$(mklinkp "$T/pic.png" "" 0 -1)"

printf 'gone' > "$TEST_DIR/gone.txt"
if share "$T/gone.txt"; then
    rm -f "$TEST_DIR/gone.txt"
    check "share server — removed file not served" test "$(http_status "$SHARE_BASE/$TOK?dl=1")" = 404
    printf 'evil' > "$OUTSIDE_DIR/evil"
    ln -s "$OUTSIDE_DIR/evil" "$TEST_DIR/gone.txt"
    check "share server — file replaced by a symlink not served" \
        test "$(http_status "$SHARE_BASE/$TOK?dl=1")" = 404
    rm -f "$TEST_DIR/gone.txt"
    assert_rpc "deleteShareLink" "FileManager" "deleteShareLink" "{\"token\":\"$TOK\"}" >/dev/null
    check "share export — deleted link removed" \
        bash -c "! jq -e --arg t '$TOK' '.links[\$t]' '$EXPORT' >/dev/null"
fi
assert_rpc_fails "deleteShareLink — unknown link" "FileManager" "deleteShareLink" \
    '{"token":"AAAAAAAAAAAAAAAAAAAAAA"}' "does not exist"
assert_rpc_fails "deleteShareLink — invalid token" "FileManager" "deleteShareLink" \
    '{"token":"../../etc"}'
assert_rpc "syncShareLinks" "FileManager" "syncShareLinks" >/dev/null
sleep 1
check "audit log — share link downloads logged by the share server" \
    bash -c "journalctl --quiet --no-pager SYSLOG_IDENTIFIER=omv-filemanager --since '$START_TS' --output=cat | grep -qF '[link:admin] share-download: $SF_NAME:/$T/pic.png (from 127.0.0.1)'"
check "audit log — failed share link passwords logged" \
    bash -c "journalctl --quiet --no-pager SYSLOG_IDENTIFIER=omv-filemanager --since '$START_TS' --output=cat | grep -qF '[link:admin] share-auth-failed: $SF_NAME:/$T/a.txt'"
set_settings '.'
check "share server — stopped when disabled" \
    bash -c "! systemctl --quiet is-active $SHARE_UNIT"
check "share export — no links while disabled" \
    test "$(jq '.links | length' "$EXPORT")" = 0

# ===========================================================================
section "Audit log"
# ===========================================================================

sleep 1
LOG=$(journalctl --quiet --no-pager SYSLOG_IDENTIFIER=omv-filemanager \
    --since "$START_TS" --output=cat 2>/dev/null || true)
for action in mkdir mkfile rename edit copy move compress extract chmod chown \
        download preview upload trash restore delete duplicate symlink \
        sharelink-create sharelink-delete; do
    check "audit log — '$action' entry" \
        bash -c "echo \"\$0\" | grep -q '^\[admin\] $action: $SF_NAME:/$T'" "$LOG"
done
assert_rpc "LogFile getList — filemanager log" "LogFile" "getList" \
    '{"id":"filemanager","start":0,"limit":null,"sortfield":null,"sortdir":null}' && \
    jcheck "LogFile getList — rows parsed into user/action/message" "$OUT" \
        'any(.data[]; .user == "admin" and .action == "mkdir")'
set_settings '.auditlog = false'
COUNT_BEFORE=$(journalctl --quiet --no-pager SYSLOG_IDENTIFIER=omv-filemanager --since "$START_TS" 2>/dev/null | wc -l)
rpc "FileManager" "mkFile" "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"quiet.txt\"}" &>/dev/null
sleep 1
COUNT_AFTER=$(journalctl --quiet --no-pager SYSLOG_IDENTIFIER=omv-filemanager --since "$START_TS" 2>/dev/null | wc -l)
check "audit log — disabled writes nothing" test "$COUNT_BEFORE" = "$COUNT_AFTER"
set_settings '.'

# ===========================================================================
section "Access checks"
# ===========================================================================

set_settings '.readonly = true'
assert_rpc "read-only mode — listing works" "FileManager" "getList" "$(list_params "$T")" >/dev/null
assert_rpc_fails "read-only mode — mkDir refused" "FileManager" "mkDir" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"ro\"}" "read-only"
assert_rpc "read-only mode — shared folder listed as ro" "FileManager" "getSharedFolderList" \
    "$GETLIST" '"access":"ro"' >/dev/null
set_settings ".sharedfolders = [\"$(cat /proc/sys/kernel/random/uuid)\"]"
assert_rpc_fails "exposed shared folders — other folder refused" "FileManager" "getList" \
    "$(list_params "$T")" "not available"
OUT=$(rpc "FileManager" "getSharedFolderList" "$GETLIST" 2>/dev/null || echo '{"data":[]}')
jcheck "exposed shared folders — not listed" "$OUT" \
    '(any(.data[]; .uuid == $u)) | not' --arg u "$SF_UUID"
set_settings '.enable = false'
assert_rpc_fails "disabled — refused" "FileManager" "getSharedFolderList" "$GETLIST" "disabled"
set_settings '.'

# ===========================================================================
section "Non-administrative user"
# ===========================================================================

if [ -z "$TEST_USER" ]; then
    info "No username given — skipped"
else
    # The file system permissions apply to users, too. Let the user write
    # to the test folder regardless of its groups, and add items it may
    # not access.
    chmod o+w "$TEST_DIR"
    mkdir "$TEST_DIR/private"
    printf 'secret' > "$TEST_DIR/private/p.txt"
    chmod 700 "$TEST_DIR/private"
    printf 'secret' > "$TEST_DIR/private.txt"
    chmod 600 "$TEST_DIR/private.txt"
    printf 'public' > "$TEST_DIR/public.txt"
    chmod 644 "$TEST_DIR/public.txt"
    mkdir "$TEST_DIR/sticky"
    chmod 1777 "$TEST_DIR/sticky"
    printf 'x' > "$TEST_DIR/sticky/s.txt"
    chmod 666 "$TEST_DIR/sticky/s.txt"
    chown root:root "$TEST_DIR/private" "$TEST_DIR/private/p.txt" \
        "$TEST_DIR/private.txt" "$TEST_DIR/public.txt" "$TEST_DIR/sticky" \
        "$TEST_DIR/sticky/s.txt"

    RPC_USER="$TEST_USER"
    assert_rpc_fails "user — refused while 'allowusers' is off" "FileManager" \
        "getSharedFolderList" "$GETLIST" "not available"
    set_settings '.allowusers = true'
    EXPECT_ACCESS=$([ "$USER_PERMS" = "7" ] && echo rw || echo ro)
    assert_rpc "user — getSharedFolderList" "FileManager" "getSharedFolderList" "$GETLIST" && \
        check "user — '$SF_NAME' listed as $EXPECT_ACCESS" \
            test "$(echo "$OUT" | jq -r --arg u "$SF_UUID" '.data[] | select(.uuid == $u) | .access')" = "$EXPECT_ACCESS"
    assert_rpc "user — getList" "FileManager" "getList" "$(list_params "$T")" >/dev/null
    assert_rpc_fails "user — settings are admin only" "FileManager" "getSettings"
    assert_rpc_fails "user — chmod is admin only" "FileManager" "chmod" \
        "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/a.txt")\",\"mode\":\"0777\",\"recursive\":false}"
    assert_rpc_fails "user — folder without permission not listed" "FileManager" \
        "getList" "$(list_params "$T/private")" "permission denied"
    assert_rpc_fails "user — file without permission not opened" "FileManager" \
        "getFileContent" "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/private.txt")\"}" \
        "permission denied"
    assert_rpc_fails "user — file without permission not downloaded" "FileManager" \
        "download" "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/private.txt")\"}" \
        "permission denied"
    assert_rpc_fails "user — file without permission not previewed" "FileManager" \
        "preview" "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/private.txt")\"}" \
        "permission denied"
    assert_rpc_fails "user — folder with unreadable contents not zipped" "FileManager" \
        "downloadArchive" "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/private")\"}" \
        "permission denied"
    assert_rpc_fails "user — checksum of unreadable file" "FileManager" "checksum" \
        "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/private.txt")\",\"algorithm\":\"sha256\"}" \
        "permission denied"
    assert_rpc "user — readable file opened" "FileManager" "getFileContent" \
        "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/public.txt")\"}" '"content":"public"' >/dev/null
    assert_rpc "user — search" "FileManager" "search" \
        "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"query\":\"p.txt\",\"start\":0,\"limit\":null}" && \
        jcheck "user — search skips folders without permission" "$OUT" \
            '(any(.data[]; .location == $l)) | not' --arg l "/$T/private"
    RPC_USER="admin"
    set_settings '.allowusers = true | .sharelinks = true'
    share "$T/pic.png"; ADMIN_TOK=$TOK
    RPC_USER="$TEST_USER"
    assert_rpc_fails "user — share links refused while not allowed for users" "FileManager" \
        "createShareLink" "$(mklinkp "$T/public.txt")" "administrators"
    set_settings '.allowusers = true | .sharelinks = true | .shareusers = true'
    if share "$T/public.txt"; then
        UTOK=$TOK
        _pass "user — createShareLink"
        check "user — link served" test "$("${CURL[@]}" "$SHARE_BASE/$UTOK?dl=1")" = "public"
        check "share export — user link carries the user's IDs" \
            test "$(jq -r --arg t "$UTOK" '.links[$t].creds.uid' "$EXPORT")" = "$(id -u "$TEST_USER")"
        chmod 600 "$TEST_DIR/public.txt"
        check "user — file the user may no longer read not served" \
            test "$(http_status "$SHARE_BASE/$UTOK?dl=1")" = 404
        chmod 644 "$TEST_DIR/public.txt"
        OUT=$(rpc "FileManager" "getShareLinkList" "$GETLIST" 2>/dev/null || echo '{"data":[]}')
        jcheck "user — getShareLinkList shows only own links" "$OUT" \
            'all(.data[]; .creator == $u) and any(.data[]; .token == $t)' --arg u "$TEST_USER" --arg t "$UTOK"
        assert_rpc_fails "user — cannot delete links of others" "FileManager" "deleteShareLink" \
            "{\"token\":\"$ADMIN_TOK\"}" "own"
        RPC_USER="admin"
        set_settings '.allowusers = false | .sharelinks = true | .shareusers = true'
        check "user — links dropped when users lose access" \
            test "$(http_status "$SHARE_BASE/$UTOK?dl=1")" = 404
        set_settings '.allowusers = true | .sharelinks = true | .shareusers = true'
        RPC_USER="$TEST_USER"
    else
        _fail "user — createShareLink"
    fi
    assert_rpc_fails "user — share link to an unreadable file" "FileManager" "createShareLink" \
        "$(mklinkp "$T/private.txt")" "permission denied"
    RPC_USER="admin"
    set_settings '.allowusers = true'
    RPC_USER="$TEST_USER"
    if [ "$USER_PERMS" = "7" ]; then
        assert_rpc_fails "user — mkDir in folder without permission" "FileManager" "mkDir" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/private")\",\"name\":\"x\"}" \
            "permission denied"
        assert_rpc_fails "user — saving a read-only file" "FileManager" "setFileContent" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/public.txt")\",\"content\":\"x\"}" \
            "permission denied"
        assert_rpc_fails "user — deleting other's file in sticky folder" "FileManager" \
            "delete" "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/sticky/s.txt")\"}" \
            "permission denied"
        assert_rpc_fails "user — permanently deleting folder with protected contents" \
            "FileManager" "delete" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/private")\",\"permanent\":true}" \
            "permission denied"
        check "user — protected items kept" \
            bash -c "[ -f '$TEST_DIR/private/p.txt' ] && [ -f '$TEST_DIR/sticky/s.txt' ] && [ \"\$(cat '$TEST_DIR/public.txt')\" = public ]"
        assert_rpc "user — mkFile" "FileManager" "mkFile" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"user.txt\"}" >/dev/null
        check "user — new file owned by $TEST_USER" \
            test "$(stat -c %U "$TEST_DIR/user.txt" 2>/dev/null)" = "$TEST_USER"
        assert_rpc "user — delete to own trash" "FileManager" "delete" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/user.txt")\"}" >/dev/null
        check "user — trashed to .recycle/$TEST_USER/" \
            test -f "$SF_PATH/.recycle/$TEST_USER/$T/user.txt"
        assert_rpc "user — getTrashList" "FileManager" "getTrashList" "$GETLIST" && \
            jcheck "user — trash list shows only own items" "$OUT" \
                'all(.data[]; .user == $u) and any(.data[]; .name == "user.txt")' --arg u "$TEST_USER"
        assert_bg "user — duplicate folder with protected contents refused" "duplicate" \
            "{\"uuid\":\"$SF_UUID\",\"paths\":\"$(tok "$T/private")\"}" fail >/dev/null
        assert_rpc_fails "user — symlink in folder without permission" "FileManager" "mkLink" \
            "$(mklink "$T/public.txt" "$T/private" "x")" "permission denied"
        assert_bg "user — disk usage of folder without permission" "diskUsage" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/private")\"}" fail >/dev/null
        assert_rpc_fails "user — purgeTrash is admin only" "FileManager" "purgeTrash" '{}' 
    else
        assert_rpc_fails "user — mkFile refused on read-only share" "FileManager" "mkFile" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"user.txt\"}" "read access"
    fi
    RPC_USER="admin"
    set_settings '.'
fi

# ===========================================================================
section "Summary"
# ===========================================================================
TOTAL=$((PASS + FAIL))
echo >&2
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC} (${TOTAL} total)" >&2
if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo -e "\n  ${RED}Failed tests:${NC}" >&2
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "    ${RED}✗${NC} $t" >&2
    done
fi
echo >&2

[ $FAIL -eq 0 ] && exit 0 || exit 1
