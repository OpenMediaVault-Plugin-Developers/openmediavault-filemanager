#!/usr/bin/env bash
# test-rpc.sh — Integration tests for openmediavault-filemanager RPC methods.
#
# Usage: sudo ./tests/test-rpc.sh <sharedfolder> [<username>]
#
# Exercises all FileManager RPC methods against a temporary test folder
# created inside the given shared folder: settings, listing, path
# confinement, create/rename, editor, trash, search, copy/move, archives,
# permissions, properties, download/preview, chunked upload, the audit log
# and the access checks (read-only mode, exposed shared folders, disabled).
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
# WARNING: This script transiently modifies the FileManager settings. Run on
# a test system or during a maintenance window.

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
START_TS=$(date '+%Y-%m-%d %H:%M:%S')
WEBGUI_USER=$(. /etc/default/openmediavault 2>/dev/null; \
    echo "${OMV_WEBGUI_FILE_OWNERGROUP_NAME:-openmediavault-webgui}")
declare -a CHUNKS=()
declare -a STAGED=()

GETLIST='{"start":0,"limit":null,"sortfield":"name","sortdir":"asc"}'

# ---------------------------------------------------------------------------
# Cleanup — always runs on exit
# ---------------------------------------------------------------------------
cleanup() {
    section "Cleanup"

    if [ -n "$ORIG_SETTINGS" ]; then
        info "Restoring original FileManager settings"
        omv-rpc -u admin "FileManager" "setSettings" "$ORIG_SETTINGS" \
            &>/dev/null || true
    fi

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

for cmd in omv-rpc jq python3 base64 journalctl; do
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
for field in enable readonly showhidden maxeditsize sharedfolders usetrash auditlog allowusers; do
    if echo "$ORIG_SETTINGS" | jq -e "has(\"$field\")" &>/dev/null; then
        _pass "getSettings — field '$field' present"
    else
        _fail "getSettings — field '$field' missing"
    fi
done
check "getSettings — sharedfolders is an array" \
    test "$(echo "$ORIG_SETTINGS" | jq -r '.sharedfolders | type')" = "array"

# Known baseline for the tests: everything on, 1 MiB editor limit.
BASE_SETTINGS=$(echo "$ORIG_SETTINGS" | jq -c '.enable = true | .readonly = false |
    .showhidden = true | .maxeditsize = 1 | .sharedfolders = [] |
    .usetrash = true | .auditlog = true | .allowusers = false')
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
}
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
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/a.txt")\"}" '"content":"linked"' >/dev/null
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
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/page.html")\"}" 'text/plain' && stage "$OUT"
assert_rpc_fails "preview — binary file" "FileManager" "preview" \
    "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/bin.dat")\"}" "cannot be previewed"

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
if ! $TRASH_EXISTED; then
    assert_rpc "emptyTrash" "FileManager" "emptyTrash" "{\"uuid\":\"$SF_UUID\"}" >/dev/null
    check "emptyTrash — trash is empty" \
        test -z "$(ls -A "$SF_PATH/.recycle" 2>/dev/null)"
else
    info "emptyTrash skipped — '$SF_PATH/.recycle' existed before the test"
fi

# ===========================================================================
section "Audit log"
# ===========================================================================

sleep 1
LOG=$(journalctl --quiet --no-pager SYSLOG_IDENTIFIER=omv-filemanager \
    --since "$START_TS" --output=cat 2>/dev/null || true)
for action in mkdir mkfile rename edit copy move compress extract chmod chown \
        download preview upload trash restore delete; do
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
    if [ "$USER_PERMS" = "7" ]; then
        assert_rpc "user — mkFile" "FileManager" "mkFile" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T")\",\"name\":\"user.txt\"}" >/dev/null
        check "user — new file owned by $TEST_USER" \
            test "$(stat -c %U "$TEST_DIR/user.txt" 2>/dev/null)" = "$TEST_USER"
        assert_rpc "user — delete to own trash" "FileManager" "delete" \
            "{\"uuid\":\"$SF_UUID\",\"path\":\"$(tok "$T/user.txt")\"}" >/dev/null
        check "user — trashed to .recycle/$TEST_USER/" \
            test -f "$SF_PATH/.recycle/$TEST_USER/$T/user.txt"
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
