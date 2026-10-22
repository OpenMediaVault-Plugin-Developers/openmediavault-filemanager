#!/usr/bin/python3
#
# This file is part of OpenMediaVault.
#
# @license   https://www.gnu.org/licenses/gpl.html GPL Version 3
# @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
# @copyright Copyright (c) 2009-2026 Volker Theile
#
# OpenMediaVault is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# OpenMediaVault is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenMediaVault. If not, see <https://www.gnu.org/licenses/>.
"""
Share link server of openmediavault-filemanager.

The server is separated from the OMV WebGUI, engined and RPC. It only
reads the share links exported by the FileManager RPC (see
writeShareExport()), which contains the links that are currently valid,
already checked with the privileges of the users that created them.

It is privilege separated like OpenSSH:

* The broker (the parent process) never touches the network. It owns the
  link data, verifies passwords, issues sessions, counts downloads and
  opens files. Every request is checked again: the link must exist, must
  not be expired or used up, the path must stay below the shared item,
  symlinks are never followed, and for links of non-administrative users
  the file system permissions and ACLs of that user apply.
* The HTTP(S) server (the child process) runs as an unprivileged user in
  an empty chroot, without capabilities. It cannot open any file; it asks
  the broker over a socket pair and gets an open file descriptor back.

Only the Python standard library is used.
"""
import base64
import collections
import email.utils
import errno
import hashlib
import hmac
import html
import http.client
import http.cookies
import http.server
import io
import json
import os
import pwd
import queue
import re
import secrets
import signal
import socket
import ssl
import stat
import struct
import sys
import threading
import time
import urllib.parse
import zipfile

EXPORT_FILE = "/var/lib/openmediavault-filemanager/share-export.json"
STATE_FILE = "/var/lib/openmediavault-filemanager-share/state.json"
CHROOT_DIR = "/run/openmediavault-filemanager-share/empty"
SERVER_USER = "omv-fm-share"

# Must match the FileManager RPC.
TRASH_DIR = ".recycle"
PART_SUFFIX = ".fmpart"

# Concurrent connections; each one gets its own channel to the broker.
MAX_CONNECTIONS = 32
MAX_MESSAGE = 65536
SESSION_LIFETIME = 12 * 3600
# Failed password attempts within THROTTLE_WINDOW seconds.
THROTTLE_WINDOW = 900
THROTTLE_PER_ADDRESS = 10
THROTTLE_PER_LINK = 30
MAX_LIST_ENTRIES = 10000
MAX_ZIP_ENTRIES = 100000
MAX_DEPTH = 64
MAX_PBKDF2_ITERATIONS = 10000000

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Already compressed formats are stored, not deflated, see writeZip().
STORED_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "webp", "mp4", "mkv", "m4v", "mov", "avi",
    "mp3", "m4a", "aac", "ogg", "flac", "zip", "gz", "tgz", "bz2", "xz",
    "zst", "7z", "rar", "iso"
}

R_OK, W_OK, X_OK = 4, 2, 1

# POSIX ACL xattr format, see acl(5) and linux/posix_acl_xattr.h.
ACL_XATTR = "system.posix_acl_access"
ACL_VERSION = 2
ACL_USER_OBJ = 0x01
ACL_USER = 0x02
ACL_GROUP_OBJ = 0x04
ACL_GROUP = 0x08
ACL_MASK = 0x10
ACL_OTHER = 0x20


def log(message):
    """
    Write a line to the journal. The unit uses the syslog identifier of
    the audit log, so the format `[user] action: details` makes the entry
    show up in Diagnostics | System Logs | File Manager.
    """
    print(CONTROL_RE.sub("?", message), flush=True)


class Denied(Exception):
    """
    A request was refused. The code is passed to the HTTP server, which
    maps it to a page that does not reveal why exactly.
    """

    def __init__(self, code="notfound"):
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------------------
# Broker
# ---------------------------------------------------------------------------

def read_acl(fd):
    """
    Get the access ACL of an open file as list of (tag, perm, id), or
    None if it has none.
    """
    try:
        data = os.getxattr(fd, ACL_XATTR)
    except OSError:
        return None
    if (len(data) < 4) or ((len(data) - 4) % 8) or \
            (struct.unpack_from("<I", data)[0] != ACL_VERSION):
        return None
    return [struct.unpack_from("<HHI", data, offset)
            for offset in range(4, len(data), 8)]


def may_access(fd, st, mask, creds):
    """
    Check the permissions of a user on an open file like the kernel does,
    including POSIX ACLs. `creds` is None for administrators, who may
    access everything, like in the file manager.
    """
    if creds is None:
        return True
    uid = creds["uid"]
    gids = set(creds["gids"])
    if st.st_uid == uid:
        return (((st.st_mode >> 6) & 7) & mask) == mask
    acl = read_acl(fd)
    if acl:
        mask_perm = 7
        for tag, perm, _ in acl:
            if tag == ACL_MASK:
                mask_perm = perm
        for tag, perm, id_ in acl:
            if (tag == ACL_USER) and (id_ == uid):
                return ((perm & mask_perm) & mask) == mask
        matched = False
        for tag, perm, id_ in acl:
            if ((tag == ACL_GROUP_OBJ) and (st.st_gid in gids)) or \
                    ((tag == ACL_GROUP) and (id_ in gids)):
                matched = True
                if ((perm & mask_perm) & mask) == mask:
                    return True
        if matched:
            return False
        for tag, perm, _ in acl:
            if tag == ACL_OTHER:
                return (perm & mask) == mask
        return False
    if st.st_gid in gids:
        return (((st.st_mode >> 3) & 7) & mask) == mask
    return ((st.st_mode & 7) & mask) == mask


def valid_name(name):
    if not isinstance(name, str) or name in ("", ".", "..") or \
            ("/" in name) or ("\0" in name):
        return False
    try:
        return len(name.encode("utf-8")) <= 255
    except UnicodeEncodeError:
        return False


class Broker:
    def __init__(self, export_file=EXPORT_FILE, state_file=STATE_FILE,
                 clock=time.time):
        self.export_file = export_file
        self.state_file = state_file
        self.clock = clock
        # Protects the download counters and the throttling data.
        self.lock = threading.Lock()
        self.config_lock = threading.Lock()
        self.secret = secrets.token_bytes(32)
        self._export = {"links": {}}
        self._export_sig = None
        self.failures = collections.defaultdict(collections.deque)
        try:
            with open(self.state_file, encoding="utf-8") as f:
                self.state = json.load(f)
            if not isinstance(self.state, dict):
                self.state = {}
        except (OSError, ValueError):
            self.state = {}

    # -- configuration -----------------------------------------------------

    def config(self):
        """
        Get the exported links, reloaded whenever the file changes, so
        new and deleted links take effect without a restart.
        """
        with self.config_lock:
            try:
                st = os.stat(self.export_file)
                sig = (st.st_mtime_ns, st.st_ino, st.st_size)
            except OSError:
                sig = None
            if sig != self._export_sig:
                self._export_sig = sig
                self._export = {"links": {}}
                if sig is not None:
                    try:
                        with open(self.export_file, encoding="utf-8") as f:
                            data = json.load(f)
                        if isinstance(data, dict) and \
                                isinstance(data.get("links"), dict):
                            self._export = data
                    except (OSError, ValueError) as e:
                        log("[share-server] error: failed to read the " +
                            "share links: {}".format(e))
            return self._export

    def downloads(self, token):
        return int(self.state.get(token, {}).get("downloads", 0))

    def link(self, token):
        if not isinstance(token, str) or not TOKEN_RE.match(token):
            raise Denied("notfound")
        link = self.config()["links"].get(token)
        if not isinstance(link, dict):
            raise Denied("notfound")
        if link.get("expires") and (link["expires"] <= self.clock()):
            raise Denied("expired")
        maxdownloads = int(link.get("maxdownloads") or 0)
        with self.lock:
            if maxdownloads and (self.downloads(token) >= maxdownloads):
                raise Denied("expired")
        return link

    # -- passwords and sessions --------------------------------------------

    def _session_mac(self, token, link, expires):
        message = "{}|{}|{}".format(token, link.get("password", ""),
                                    expires).encode()
        return hmac.new(self.secret, message, hashlib.sha256).digest()[:16]

    def make_session(self, token, link):
        expires = int(self.clock()) + SESSION_LIFETIME
        value = struct.pack(">Q", expires) + \
            self._session_mac(token, link, expires)
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    def session_ok(self, token, link, session):
        if not link.get("password"):
            return True
        if not isinstance(session, str) or (len(session) > 64):
            return False
        try:
            value = base64.urlsafe_b64decode(session + "=" *
                                             (-len(session) % 4))
        except (ValueError, TypeError):
            return False
        if len(value) != 24:
            return False
        expires = struct.unpack(">Q", value[:8])[0]
        if expires <= self.clock():
            return False
        return hmac.compare_digest(value[8:],
                                   self._session_mac(token, link, expires))

    @staticmethod
    def check_password(encoded, password):
        try:
            algorithm, iterations, salt, digest = encoded.split("$")
            iterations = int(iterations)
            salt = base64.b64decode(salt, validate=True)
            digest = base64.b64decode(digest, validate=True)
        except (ValueError, AttributeError):
            return False
        if (algorithm != "pbkdf2_sha256") or not digest or \
                not (0 < iterations <= MAX_PBKDF2_ITERATIONS):
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8", "replace"), salt, iterations,
            len(digest))
        return hmac.compare_digest(candidate, digest)

    def _throttled(self, key):
        limit = THROTTLE_PER_LINK if key[0] == "link" else \
            THROTTLE_PER_ADDRESS
        now = self.clock()
        with self.lock:
            attempts = self.failures[key]
            while attempts and (attempts[0] < now - THROTTLE_WINDOW):
                attempts.popleft()
            if not attempts:
                del self.failures[key]
                return False
            return len(attempts) >= limit

    def _record_failure(self, *keys):
        with self.lock:
            for key in keys:
                self.failures[key].append(self.clock())

    # -- file system -------------------------------------------------------

    def _check_segments(self, segments):
        if not isinstance(segments, list) or (len(segments) > MAX_DEPTH):
            raise Denied("notfound")
        showhidden = bool(self.config().get("showhidden", True))
        for name in segments:
            if not valid_name(name) or name.endswith(PART_SUFFIX) or \
                    (not showhidden and name.startswith(".")):
                raise Denied("notfound")

    def resolve(self, link, segments):
        """
        Open the shared item, or an item below a shared folder. Every
        path component is opened relative to its parent with O_NOFOLLOW,
        so symlinks are never followed and the path cannot be redirected
        outside of the shared item between checks.
        @return (fd, stat result); the caller closes the fd.
        """
        self._check_segments(segments)
        if segments and (link.get("type") != "dir"):
            raise Denied("notfound")
        base = [] if link["path"] == "." else link["path"].split("/")
        components = base + segments
        if components and (components[0] == TRASH_DIR):
            raise Denied("notfound")
        creds = link.get("creds")
        try:
            fd = os.open(link["root"], os.O_RDONLY | os.O_DIRECTORY |
                         os.O_CLOEXEC)
        except OSError:
            raise Denied("notfound")
        try:
            st = os.fstat(fd)
            for i, name in enumerate(components):
                if not stat.S_ISDIR(st.st_mode) or \
                        not may_access(fd, st, X_OK, creds):
                    raise Denied("notfound")
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | \
                    os.O_NONBLOCK | os.O_NOCTTY
                if i < len(components) - 1:
                    flags |= os.O_DIRECTORY
                try:
                    child = os.open(name, flags, dir_fd=fd)
                except OSError:
                    raise Denied("notfound")
                os.close(fd)
                fd = child
                st = os.fstat(fd)
            kind = "dir" if stat.S_ISDIR(st.st_mode) else \
                "file" if stat.S_ISREG(st.st_mode) else None
            if (kind is None) or (not segments and kind != link["type"]):
                raise Denied("notfound")
            if not may_access(fd, st, (R_OK | X_OK) if kind == "dir" else
                              R_OK, creds):
                raise Denied("notfound")
            return fd, st
        except BaseException:
            os.close(fd)
            raise

    def _entries(self, fd, at_share_root, creds):
        """
        Yield (name, kind, stat result, child fd or None) of the entries
        of an open folder that may be shown. Child fds of folders are
        returned so callers can descend; they must close them.
        """
        showhidden = bool(self.config().get("showhidden", True))
        with os.scandir(fd) as it:
            for entry in it:
                name = entry.name
                if not valid_name(name) or name.endswith(PART_SUFFIX) or \
                        (not showhidden and name.startswith(".")) or \
                        (at_share_root and name == TRASH_DIR):
                    continue
                try:
                    if entry.is_symlink():
                        continue
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(est.st_mode):
                    kind = "dir"
                elif stat.S_ISREG(est.st_mode):
                    kind = "file"
                else:
                    continue
                child = None
                if (kind == "dir") or (creds is not None):
                    try:
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                        os.O_CLOEXEC | os.O_NONBLOCK |
                                        os.O_NOCTTY, dir_fd=fd)
                        est = os.fstat(child)
                    except OSError:
                        continue
                    if not may_access(child, est, (R_OK | X_OK) if
                                      kind == "dir" else R_OK, creds):
                        os.close(child)
                        continue
                    if kind == "file":
                        os.close(child)
                        child = None
                yield name, kind, est, child

    def list_dir(self, link, fd, at_share_root):
        result = []
        for name, kind, st, child in self._entries(fd, at_share_root,
                                                   link.get("creds")):
            if child is not None:
                os.close(child)
            result.append({
                "name": name,
                "type": kind,
                "size": st.st_size if kind == "file" else -1,
                "mtime": int(st.st_mtime)
            })
            if len(result) >= MAX_LIST_ENTRIES:
                break
        result.sort(key=lambda e: (e["type"] != "dir", e["name"].casefold(),
                                   e["name"]))
        return result

    def walk(self, link, fd, at_share_root):
        """
        Get all files and folders below an open folder, for a ZIP archive.
        Takes ownership of the fd.
        """
        result = []
        stack = [(fd, [], at_share_root)]
        try:
            while stack:
                dfd, prefix, at_root = stack.pop()
                try:
                    for name, kind, st, child in self._entries(
                            dfd, at_root, link.get("creds")):
                        path = prefix + [name]
                        result.append({
                            "path": path,
                            "type": kind,
                            "size": st.st_size if kind == "file" else -1,
                            "mtime": int(st.st_mtime)
                        })
                        if len(result) > MAX_ZIP_ENTRIES:
                            if child is not None:
                                os.close(child)
                            raise Denied("toolarge")
                        if child is not None:
                            if len(path) >= MAX_DEPTH:
                                os.close(child)
                                continue
                            stack.append((child, path, False))
                finally:
                    os.close(dfd)
        finally:
            for dfd, _, _ in stack:
                os.close(dfd)
        return result

    # -- downloads ---------------------------------------------------------

    def _save_state(self):
        links = self.config()["links"]
        self.state = {k: v for k, v in self.state.items() if k in links}
        tmp = self.state_file + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.state, f)
            os.replace(tmp, self.state_file)
        except OSError as e:
            log("[share-server] error: failed to save the download " +
                "counters: {}".format(e))

    def register_download(self, token, link):
        maxdownloads = int(link.get("maxdownloads") or 0)
        with self.lock:
            entry = self.state.setdefault(token, {"downloads": 0})
            if maxdownloads and (entry.get("downloads", 0) >= maxdownloads):
                raise Denied("expired")
            entry["downloads"] = entry.get("downloads", 0) + 1
            entry["lastaccess"] = int(self.clock())
            self._save_state()

    def audit(self, link, action, segments, address):
        if not self.config().get("auditlog", True):
            return
        rel = "/".join(([] if link["path"] == "." else [link["path"]]) +
                       segments)
        log("[link:{}] {}: {}:/{} (from {})".format(
            link.get("creator", "?"), action, link.get("sharename", "?"),
            rel, address))

    # -- requests ----------------------------------------------------------

    def _name(self, link, segments):
        if segments:
            return segments[-1]
        if link["path"] == ".":
            return link.get("sharename", "share")
        return link["path"].rsplit("/", 1)[-1]

    def handle(self, msg):
        """
        Handle a request of the HTTP server.
        @return (response, fd or None)
        """
        if not isinstance(msg, dict):
            raise Denied("invalid")
        op = msg.get("op")
        token = msg.get("token")
        address = str(msg.get("address", "?"))[:64]
        segments = msg.get("path", [])
        link = self.link(token)
        if op == "auth":
            if self._throttled(("address", address)) or \
                    self._throttled(("link", token)):
                raise Denied("throttled")
            if not link.get("password"):
                return {"ok": True, "session": ""}, None
            password = msg.get("password")
            if isinstance(password, str) and \
                    self.check_password(link["password"], password):
                return {"ok": True,
                        "session": self.make_session(token, link)}, None
            self._record_failure(("address", address), ("link", token))
            self.audit(link, "share-auth-failed", [], address)
            raise Denied("badpassword")
        if not self.session_ok(token, link, msg.get("session")):
            if op == "info":
                return {"ok": True, "protected": True,
                        "authorized": False}, None
            raise Denied("unauthorized")
        fd, st = self.resolve(link, segments)
        kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
        at_share_root = (link["path"] == ".") and not segments
        meta = {
            "ok": True,
            "protected": bool(link.get("password")),
            "authorized": True,
            "type": kind,
            "name": self._name(link, segments),
            "size": st.st_size if kind == "file" else -1,
            "mtime": int(st.st_mtime)
        }
        if op == "info":
            try:
                if kind == "dir":
                    meta["entries"] = self.list_dir(link, fd, at_share_root)
            finally:
                os.close(fd)
            return meta, None
        if op == "open":
            if kind != "file":
                os.close(fd)
                raise Denied("notfound")
            if msg.get("count"):
                try:
                    self.register_download(token, link)
                except BaseException:
                    os.close(fd)
                    raise
                self.audit(link, "share-download", segments, address)
            return meta, fd
        if op == "walk":
            if kind != "dir":
                os.close(fd)
                raise Denied("notfound")
            entries = self.walk(link, fd, at_share_root)
            self.register_download(token, link)
            self.audit(link, "share-download", segments, address)
            meta["entries"] = entries
            return meta, None
        os.close(fd)
        raise Denied("invalid")


def send_response(sock, resp, fd=None):
    """
    Send a response to the HTTP server. Long entry lists are split into
    several messages, each fitting into one SOCK_SEQPACKET datagram.
    """
    entries = resp.pop("entries", None)
    if entries is None:
        data = json.dumps(resp).encode()
        if fd is None:
            sock.send(data)
        else:
            socket.send_fds(sock, [data], [fd])
        return
    chunk, size, first = [], 0, True
    for entry in entries:
        encoded = len(json.dumps(entry)) + 2
        if chunk and (size + encoded > MAX_MESSAGE // 2):
            msg = dict(resp) if first else {}
            msg.update({"entries": chunk, "more": True})
            sock.send(json.dumps(msg).encode())
            chunk, size, first = [], 0, False
        chunk.append(entry)
        size += encoded
    msg = dict(resp) if first else {}
    msg.update({"entries": chunk, "more": False})
    sock.send(json.dumps(msg).encode())


def serve_channel(broker, sock):
    """
    Answer the requests sent over one channel until it is closed.
    """
    while True:
        try:
            data = sock.recv(MAX_MESSAGE)
        except OSError:
            return
        if not data:
            return
        fd = None
        try:
            try:
                resp, fd = broker.handle(json.loads(data))
            except Denied as e:
                resp = {"ok": False, "error": e.code}
            except Exception as e:  # pylint: disable=broad-except
                log("[share-server] error: {}".format(e))
                resp = {"ok": False, "error": "internal"}
            send_response(sock, resp, fd)
        except OSError:
            return
        finally:
            if fd is not None:
                os.close(fd)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class BrokerGone(Exception):
    pass


class Channels:
    """
    The pool of channels to the broker. Each request thread uses one
    channel exclusively until it got the complete response.
    """

    def __init__(self, socks):
        self.pool = queue.Queue()
        for sock in socks:
            self.pool.put(sock)

    def call(self, msg):
        sock = self.pool.get()
        try:
            sock.send(json.dumps(msg).encode())
            data, fds, _, _ = socket.recv_fds(sock, MAX_MESSAGE, 1)
            if not data:
                raise BrokerGone()
            resp = json.loads(data)
            while resp.pop("more", False):
                data = sock.recv(MAX_MESSAGE)
                if not data:
                    raise BrokerGone()
                more = json.loads(data)
                resp["entries"].extend(more["entries"])
                resp["more"] = more.get("more", False)
            return resp, (fds[0] if fds else None)
        finally:
            self.pool.put(sock)


STYLE = """
:root { color-scheme: light dark; --fg: #1d2129; --bg: #f4f6f8;
  --card: #fff; --muted: #66707a; --line: #e2e6ea; --accent: #1565c0; }
@media (prefers-color-scheme: dark) { :root { --fg: #e6e9ec;
  --bg: #15181c; --card: #1f2329; --muted: #9aa3ad; --line: #30363d;
  --accent: #64a8f0; } }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 system-ui, sans-serif; color: var(--fg);
  background: var(--bg); }
main { max-width: 860px; margin: 40px auto; padding: 0 16px; }
.card { background: var(--card); border: 1px solid var(--line);
  border-radius: 10px; padding: 24px; }
h1 { font-size: 20px; margin: 0 0 4px; word-break: break-word; }
p.muted, .muted { color: var(--muted); }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.button { display: inline-block; background: var(--accent); color: #fff;
  border: 0; border-radius: 6px; padding: 9px 18px; font: inherit;
  cursor: pointer; text-decoration: none; }
.button:hover { text-decoration: none; filter: brightness(1.1); }
table { width: 100%; border-collapse: collapse; margin-top: 16px; }
td { padding: 8px 6px; border-top: 1px solid var(--line);
  word-break: break-word; }
td.num { text-align: right; white-space: nowrap; color: var(--muted); }
input[type=password] { font: inherit; padding: 8px 10px; width: 100%;
  max-width: 320px; border: 1px solid var(--line); border-radius: 6px;
  background: var(--bg); color: var(--fg); margin: 8px 8px 8px 0; }
.error { color: #c62828; }
.top { display: flex; justify-content: space-between; align-items: center;
  gap: 16px; flex-wrap: wrap; }
"""

STATUS_PAGES = {
    "notfound": (404, "Link not found",
                 "This link does not exist or is no longer available."),
    "expired": (410, "Link expired", "This link has expired."),
    "throttled": (429, "Too many attempts",
                  "Too many wrong passwords. Please try again later."),
    "toolarge": (413, "Folder too large",
                 "This folder contains too many items to be downloaded as "
                 "one archive. Download the items separately."),
    "internal": (500, "Error", "Something went wrong. Please try again "
                 "later.")
}


def format_size(size):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return ("{:.0f} {}" if unit == "B" else "{:.1f} {}").format(
                size, unit)
        size /= 1024
    return ""


def content_disposition(name):
    fallback = "".join(c if (32 <= ord(c) < 127) and c not in "\"\\%" else
                       "_" for c in name)
    return "attachment; filename=\"{}\"; filename*=UTF-8''{}".format(
        fallback, urllib.parse.quote(name, safe=""))


def cookie_name(token):
    return "fms_" + hashlib.sha256(token.encode()).hexdigest()[:16]


class ZipOutput:
    """
    Unseekable file object for zipfile, which then writes data
    descriptors, so the archive is streamed while it is created.
    """

    def __init__(self, wfile):
        self.wfile = wfile

    def write(self, data):
        self.wfile.write(data)
        return len(data)

    def flush(self):
        self.wfile.flush()


class ShareHandler(http.server.BaseHTTPRequestHandler):
    server_version = "omv-filemanager-share"
    sys_version = ""
    # One request per connection.
    protocol_version = "HTTP/1.0"
    timeout = 60

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        # Downloads are logged by the broker; do not log addresses and
        # paths of every request.
        pass

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    # -- responses ---------------------------------------------------------

    def security_headers(self, html_page=True):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("X-Frame-Options", "DENY")
        if html_page:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "form-action 'self'; frame-ancestors 'none'; "
                "base-uri 'none'")
        else:
            self.send_header("Content-Security-Policy", "sandbox")
        if self.server.tls is not None:
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def page(self, status, title, body, headers=None):
        data = ("<!DOCTYPE html><html lang=\"en\"><head><meta charset="
                "\"utf-8\"><meta name=\"viewport\" content=\"width="
                "device-width, initial-scale=1\"><meta name=\"robots\" "
                "content=\"noindex\"><title>{}</title><style>{}</style>"
                "</head><body><main>{}</main></body></html>").format(
                    html.escape(title), STYLE, body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or []):
            self.send_header(key, value)
        self.security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def status_page(self, code):
        status, title, text = STATUS_PAGES.get(code, STATUS_PAGES["notfound"])
        self.page(status, title, "<div class=\"card\"><h1>{}</h1><p class="
                  "\"muted\">{}</p></div>".format(html.escape(title),
                                                  html.escape(text)))

    def redirect(self, location, headers=None):
        self.send_response(303 if self.command == "POST" else 301)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for key, value in (headers or []):
            self.send_header(key, value)
        self.security_headers()
        self.end_headers()

    def password_page(self, error=False):
        self.page(401, "Password required", (
            "<div class=\"card\"><h1>Password required</h1><p class="
            "\"muted\">This link is protected by a password.</p>{}"
            "<form method=\"post\" action=\"\"><input type=\"password\" "
            "name=\"password\" autofocus required autocomplete="
            "\"current-password\" aria-label=\"Password\"><button class="
            "\"button\" type=\"submit\">Continue</button></form></div>"
        ).format("<p class=\"error\">Wrong password.</p>" if error else ""))

    def file_page(self, info):
        self.page(200, info["name"], (
            "<div class=\"card\"><h1>{}</h1><p class=\"muted\">{} &middot; "
            "{}</p><a class=\"button\" href=\"?dl=1\">Download</a></div>"
        ).format(html.escape(info["name"]), format_size(info["size"]),
                 html.escape(email.utils.formatdate(info["mtime"],
                                                    usegmt=True))))

    def dir_page(self, info, segments):
        rows = []
        if segments:
            rows.append("<tr><td colspan=\"3\"><a href=\"../\">&larr; "
                        "Parent folder</a></td></tr>")
        for entry in info["entries"]:
            href = urllib.parse.quote(entry["name"], safe="")
            if entry["type"] == "dir":
                rows.append(
                    "<tr><td><a href=\"{}/\">{}/</a></td><td class=\"num\">"
                    "</td><td class=\"num\"><a href=\"{}/?zip=1\">ZIP</a>"
                    "</td></tr>".format(href, html.escape(entry["name"]),
                                        href))
            else:
                rows.append(
                    "<tr><td><a href=\"{}?dl=1\">{}</a></td><td class="
                    "\"num\">{}</td><td class=\"num\"></td></tr>".format(
                        href, html.escape(entry["name"]),
                        format_size(entry["size"])))
        if not info["entries"]:
            rows.append("<tr><td colspan=\"3\" class=\"muted\">This folder "
                        "is empty.</td></tr>")
        self.page(200, info["name"], (
            "<div class=\"card\"><div class=\"top\"><div><h1>{}</h1>"
            "<p class=\"muted\">/{}</p></div><a class=\"button\" href="
            "\"?zip=1\">Download all (ZIP)</a></div><table>{}</table></div>"
        ).format(html.escape(info["name"]),
                 html.escape("/".join(segments)), "".join(rows)))

    # -- request handling --------------------------------------------------

    def address(self):
        address = self.client_address[0]
        return address[7:] if address.startswith("::ffff:") else address

    def session(self, token):
        try:
            cookies = http.cookies.SimpleCookie(self.headers.get("Cookie",
                                                                 ""))
        except http.cookies.CookieError:
            return ""
        morsel = cookies.get(cookie_name(token))
        return morsel.value if morsel else ""

    def call(self, msg):
        try:
            return self.server.channels.call(msg)
        except BrokerGone:
            # The broker is gone, the service is restarted.
            os._exit(1)

    def route(self, method):
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path == "/robots.txt" and method == "GET":
            data = b"User-agent: *\nDisallow: /\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if not path.startswith("/s/"):
            return self.status_page("notfound")
        raw = path[3:].split("/")
        token, raw = raw[0], raw[1:]
        trailing = bool(raw) and (raw[-1] == "")
        if trailing:
            raw = raw[:-1]
        try:
            segments = [urllib.parse.unquote(s, errors="strict")
                        for s in raw]
        except UnicodeDecodeError:
            return self.status_page("notfound")
        if not TOKEN_RE.match(token) or \
                not all(valid_name(s) for s in segments):
            return self.status_page("notfound")
        # Relative URL of the requested page itself.
        own = "./" if trailing else urllib.parse.quote(
            segments[-1] if segments else token, safe="")
        query = urllib.parse.parse_qs(parts.query, max_num_fields=4)
        base = {"token": token, "path": segments, "address": self.address(),
                "session": self.session(token)}
        if method == "POST":
            return self.authenticate(base, own)
        info, _ = self.call(dict(base, op="info"))
        if not info.get("ok"):
            return self.status_page(info.get("error"))
        if not info.get("authorized"):
            return self.password_page()
        if info["type"] == "dir":
            if not trailing:
                return self.redirect(own + "/")
            if "zip" in query:
                return self.send_zip(base, info)
            return self.dir_page(info, segments)
        if trailing:
            return self.status_page("notfound")
        if "dl" in query:
            return self.send_file(base)
        return self.file_page(info)

    def authenticate(self, base, own):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not (0 <= length <= 4096):
            return self.status_page("notfound")
        form = urllib.parse.parse_qs(
            self.rfile.read(length).decode("utf-8", "replace"),
            max_num_fields=4)
        resp, _ = self.call(dict(base, op="auth", password=form.get(
            "password", [""])[0]))
        if resp.get("ok"):
            cookie = "{}={}; Max-Age={}; Path=/; HttpOnly; SameSite=" \
                "Strict{}".format(cookie_name(base["token"]),
                                  resp["session"], SESSION_LIFETIME,
                                  "; Secure" if self.server.tls else "")
            return self.redirect(own, [("Set-Cookie", cookie)])
        if resp.get("error") == "badpassword":
            return self.password_page(error=True)
        return self.status_page(resp.get("error"))

    def send_file(self, base):
        resp, fd = self.call(dict(base, op="open", count=True))
        if not resp.get("ok") or fd is None:
            if fd is not None:
                os.close(fd)
            return self.status_page(resp.get("error"))
        with os.fdopen(fd, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition",
                             content_disposition(resp["name"]))
            self.security_headers(html_page=False)
            self.end_headers()
            self.wfile.flush()
            if size:
                self.connection.sendfile(f, 0, size)

    def send_zip(self, base, info):
        resp, _ = self.call(dict(base, op="walk"))
        if not resp.get("ok"):
            return self.status_page(resp.get("error"))
        name = info["name"]
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition",
                         content_disposition(name + ".zip"))
        self.security_headers(html_page=False)
        self.end_headers()
        with zipfile.ZipFile(ZipOutput(self.wfile), "w",
                             zipfile.ZIP_DEFLATED, allowZip64=True,
                             compresslevel=6) as zf:
            for entry in resp["entries"]:
                arcname = "/".join([name] + entry["path"])
                date_time = time.localtime(max(entry["mtime"],
                                               315532800))[:6]
                if entry["type"] == "dir":
                    zi = zipfile.ZipInfo(arcname + "/", date_time)
                    zi.external_attr = (0o40755 << 16) | 0x10
                    zf.writestr(zi, b"")
                    continue
                fresp, fd = self.call(dict(base, op="open", count=False,
                                           path=base["path"] +
                                           entry["path"]))
                if not fresp.get("ok") or fd is None:
                    # Removed or changed in the meantime.
                    if fd is not None:
                        os.close(fd)
                    continue
                with os.fdopen(fd, "rb") as f:
                    zi = zipfile.ZipInfo(arcname, date_time)
                    zi.external_attr = 0o100644 << 16
                    zi.file_size = os.fstat(f.fileno()).st_size
                    ext = arcname.rsplit(".", 1)[-1].lower() \
                        if "." in entry["path"][-1] else ""
                    zi.compress_type = zipfile.ZIP_STORED \
                        if ext in STORED_EXTENSIONS else zipfile.ZIP_DEFLATED
                    with zf.open(zi, "w") as dest:
                        while True:
                            chunk = f.read(1024 * 1024)
                            if not chunk:
                                break
                            dest.write(chunk)


class ShareServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, channels, tls=None, family=socket.AF_INET6):
        self.address_family = family
        self.channels = channels
        self.tls = tls
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, ShareHandler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            # Accept IPv4 connections, too.
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY,
                                   0)
        super().server_bind()

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def finish_request(self, request, client_address):
        # The TLS handshake runs in the request thread, so a slow client
        # cannot block the others.
        request.settimeout(ShareHandler.timeout)
        if self.tls is not None:
            request = self.tls.wrap_socket(request, server_side=True)
        try:
            self.RequestHandlerClass(request, client_address, self)
        finally:
            if self.tls is not None:
                request.close()

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, OSError)):
            return
        log("[share-server] error: {}: {}".format(type(exc).__name__, exc))


def make_server(port, channels, tls=None, host=None):
    """
    Bind the server to all addresses, IPv6 and IPv4 if possible.
    """
    if host is not None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        return ShareServer((host, port), channels, tls, family)
    try:
        return ShareServer(("::", port), channels, tls, socket.AF_INET6)
    except OSError as e:
        if e.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            raise
    return ShareServer(("0.0.0.0", port), channels, tls, socket.AF_INET)


def make_tls_context(cert, key):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def warm_up():
    """
    Load everything that is loaded lazily before entering the chroot,
    where no module or file can be read anymore.
    """
    time.localtime()
    email.utils.formatdate(usegmt=True)
    http.client.parse_headers(io.BytesIO(b"Cookie: a=b\r\n\r\n"))
    http.cookies.SimpleCookie("a=b")
    urllib.parse.parse_qs("a=%C3%A4", max_num_fields=4)
    urllib.parse.unquote("%C3%A4", errors="strict")
    with zipfile.ZipFile(io.BytesIO(), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a", b"a")
    "a".encode("idna")
    html.escape("<")


def drop_privileges(user=SERVER_USER, chroot_dir=CHROOT_DIR):
    pw = pwd.getpwnam(user)
    os.makedirs(chroot_dir, mode=0o555, exist_ok=True)
    st = os.lstat(chroot_dir)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or \
            (st.st_mode & 0o022) or os.listdir(chroot_dir):
        raise RuntimeError("{} is not an empty folder owned by root".format(
            chroot_dir))
    os.chroot(chroot_dir)
    os.chdir("/")
    os.setgroups([])
    os.setresgid(pw.pw_gid, pw.pw_gid, pw.pw_gid)
    # Changing all user IDs away from 0 clears all capabilities.
    os.setresuid(pw.pw_uid, pw.pw_uid, pw.pw_uid)
    try:
        os.setuid(0)
    except PermissionError:
        return
    raise RuntimeError("Failed to drop privileges")


def sd_notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.connect(address)
        s.sendall(message.encode())


def run_child(config, socks, ready_fd, parent_pid):
    try:
        tls = None
        if config.get("tls"):
            tls = make_tls_context(config["tls"]["cert"],
                                   config["tls"]["key"])
        server = make_server(int(config.get("port", 8095)), Channels(socks),
                             tls)
        warm_up()
        drop_privileges()
    except Exception as e:  # pylint: disable=broad-except
        log("[share-server] error: failed to start: {}".format(e))
        os._exit(1)

    def watchdog():
        while True:
            if os.getppid() != parent_pid:
                os._exit(1)
            time.sleep(2)

    threading.Thread(target=watchdog, daemon=True).start()
    os.write(ready_fd, b"1")
    os.close(ready_fd)
    try:
        server.serve_forever()
    finally:
        os._exit(1)


def main():
    if os.geteuid() != 0:
        print("Must be run as root.", file=sys.stderr)
        return 1
    broker = Broker()
    config = broker.config()
    if not os.path.exists(EXPORT_FILE):
        log("[share-server] error: {} does not exist".format(EXPORT_FILE))
        return 1
    pairs = [socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
             for _ in range(MAX_CONNECTIONS)]
    ready_r, ready_w = os.pipe()
    parent_pid = os.getpid()
    # Fork before any thread is started.
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        for ours, _ in pairs:
            ours.close()
        run_child(config, [theirs for _, theirs in pairs], ready_w,
                  parent_pid)
    os.close(ready_w)
    for _, theirs in pairs:
        theirs.close()
    for ours, _ in pairs:
        threading.Thread(target=serve_channel, args=(broker, ours),
                         daemon=True).start()
    if os.read(ready_r, 1) != b"1":
        os.waitpid(pid, 0)
        return 1
    os.close(ready_r)
    port = config.get("port", 8095)
    log("[share-server] start: listening on port {} ({})".format(
        port, "HTTPS" if config.get("tls") else "HTTP"))
    sd_notify("READY=1")

    def terminate(signum, frame):  # pylint: disable=unused-argument
        os.kill(pid, signal.SIGTERM)
        sys.exit(0)

    signal.signal(signal.SIGTERM, terminate)
    _, status = os.waitpid(pid, 0)
    log("[share-server] error: the HTTP server exited ({})".format(status))
    return 1


if __name__ == "__main__":
    sys.exit(main())
