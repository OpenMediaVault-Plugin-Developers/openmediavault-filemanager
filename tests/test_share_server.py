#!/usr/bin/env python3
"""
Tests for the share link server (usr/lib/openmediavault-filemanager/
share_server.py).

Usage: python3 -m unittest discover -s tests -p 'test_share_server.py'
       python3 tests/test_share_server.py

Runs as an unprivileged user without OMV: the broker and the HTTP server
run in-process, connected by socket pairs like in production, and serve
a temporary folder. Privilege separation itself (chroot, user change) is
covered by tests/test-rpc.sh on an OMV system.
"""
import base64
import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "usr", "lib",
                                "openmediavault-filemanager"))
import share_server  # noqa: E402  pylint: disable=wrong-import-position

TOKEN_FILE = "A" * 22
TOKEN_DIR = "B" * 22
TOKEN_PW = "C" * 22
TOKEN_ROOT = "D" * 22
TOKEN_LIMIT = "E" * 22
TOKEN_EXPIRED = "F" * 22
TOKEN_USER = "G" * 22
TOKEN_TYPE = "H" * 22
TOKEN_NEW = "I" * 22
PASSWORD = "s3cret pässword"


def pbkdf2(password, iterations=1000):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                                 iterations, 32)
    return "pbkdf2_sha256${}${}${}".format(
        iterations, base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode())


class Clock:
    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now


class ShareServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fm-share-test-")
        self.root = os.path.join(self.tmp, "Share")
        self.outside = os.path.join(self.tmp, "outside")
        os.makedirs(os.path.join(self.root, "docs", "sub"))
        os.makedirs(os.path.join(self.root, ".recycle", "admin"))
        os.makedirs(self.outside)
        self.write("docs/a.txt", "hello")
        self.write("docs/sub/b.txt", "world")
        self.write("docs/.hidden", "hidden")
        self.write("docs/.c.txt.fmpart", "partial")
        self.write("docs/photo.jpg", "jpeg")
        self.write(".recycle/admin/trashed.txt", "trash")
        self.write("report.pdf", "%PDF-1.4")
        self.write("private.txt", "private")
        os.chmod(os.path.join(self.root, "private.txt"), 0o600)
        with open(os.path.join(self.outside, "secret"), "w") as f:
            f.write("secret")
        os.symlink(self.outside, os.path.join(self.root, "docs", "escape"))
        os.symlink(os.path.join(self.outside, "secret"),
                   os.path.join(self.root, "docs", "leak.txt"))
        os.symlink("a.txt", os.path.join(self.root, "docs", "alias.txt"))
        os.mkfifo(os.path.join(self.root, "docs", "fifo"))
        self.clock = Clock()
        self.logs = []
        self.orig_log = share_server.log
        share_server.log = self.logs.append
        self.export_file = os.path.join(self.tmp, "export.json")
        self.state_file = os.path.join(self.tmp, "state.json")
        self.links = {
            TOKEN_FILE: self.link("report.pdf", "file"),
            TOKEN_DIR: self.link("docs", "dir"),
            TOKEN_PW: self.link("docs/a.txt", "file",
                                password=pbkdf2(PASSWORD)),
            TOKEN_ROOT: self.link(".", "dir"),
            TOKEN_LIMIT: self.link("docs/a.txt", "file", maxdownloads=2),
            TOKEN_EXPIRED: self.link("docs/a.txt", "file",
                                     expires=int(self.clock.now) - 10),
            TOKEN_USER: self.link(".", "dir", creds={
                "uid": os.getuid() + 12345, "gids": []}),
            TOKEN_TYPE: self.link("docs", "file"),
        }
        self.write_export()
        self.broker = share_server.Broker(self.export_file, self.state_file,
                                          clock=self.clock)
        pairs = [socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                 for _ in range(4)]
        self.socks = [s for pair in pairs for s in pair]
        for ours, _ in pairs:
            threading.Thread(target=share_server.serve_channel,
                             args=(self.broker, ours), daemon=True).start()
        self.channels = share_server.Channels([t for _, t in pairs])
        self.start_server()

    def start_server(self, tls=None):
        self.server = share_server.make_server(0, self.channels, tls,
                                               host="127.0.0.1")
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()

    def tearDown(self):
        share_server.log = self.orig_log
        self.server.shutdown()
        self.server.server_close()
        for s in self.socks:
            s.close()
        for dirpath, dirnames, _ in os.walk(self.tmp):
            for d in dirnames:
                try:
                    os.chmod(os.path.join(dirpath, d), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.tmp)

    # -- helpers -----------------------------------------------------------

    def write(self, rel, content):
        with open(os.path.join(self.root, rel), "w") as f:
            f.write(content)

    def link(self, path, kind, password="", maxdownloads=0, expires=0,
             creds=None):
        return {
            "root": self.root, "sharename": "Share", "path": path,
            "type": kind, "expires": expires, "password": password,
            "maxdownloads": maxdownloads, "creator": "admin",
            "creds": creds
        }

    def write_export(self, showhidden=False):
        tmp = self.export_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"version": 1, "port": 0, "tls": None,
                       "showhidden": showhidden, "auditlog": True,
                       "links": self.links}, f)
        os.replace(tmp, self.export_file)
        # Make sure the change is detected even within the same tick.
        st = os.stat(self.export_file)
        os.utime(self.export_file, ns=(st.st_atime_ns,
                                       st.st_mtime_ns + 1000))

    def request(self, path, method="GET", body=None, headers=None,
                context=None):
        if context is None:
            conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                              timeout=10)
        else:
            conn = http.client.HTTPSConnection("127.0.0.1", self.port,
                                               timeout=10, context=context)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def login(self, token, password=PASSWORD):
        resp, _ = self.request(
            "/s/" + token, "POST", body="password=" +
            __import__("urllib.parse").parse.quote(password),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        return resp

    # -- file links --------------------------------------------------------

    def test_file_page_and_download(self):
        resp, data = self.request("/s/" + TOKEN_FILE)
        self.assertEqual(resp.status, 200)
        self.assertIn(b"report.pdf", data)
        self.assertIn("default-src 'none'",
                      resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")
        resp, data = self.request("/s/{}?dl=1".format(TOKEN_FILE))
        self.assertEqual(resp.status, 200)
        self.assertEqual(data, b"%PDF-1.4")
        self.assertEqual(resp.getheader("Content-Type"),
                         "application/octet-stream")
        self.assertTrue(resp.getheader("Content-Disposition").startswith(
            "attachment;"))
        self.assertEqual(resp.getheader("Content-Security-Policy"),
                         "sandbox")
        self.assertEqual(resp.getheader("X-Content-Type-Options"),
                         "nosniff")

    def test_download_counter_saved(self):
        self.request("/s/{}?dl=1".format(TOKEN_FILE))
        self.request("/s/{}?dl=1".format(TOKEN_FILE))
        with open(self.state_file) as f:
            state = json.load(f)
        self.assertEqual(state[TOKEN_FILE]["downloads"], 2)
        # Viewing the page is not a download.
        self.request("/s/" + TOKEN_FILE)
        with open(self.state_file) as f:
            self.assertEqual(json.load(f)[TOKEN_FILE]["downloads"], 2)

    def test_max_downloads(self):
        for _ in range(2):
            resp, data = self.request("/s/{}?dl=1".format(TOKEN_LIMIT))
            self.assertEqual((resp.status, data), (200, b"hello"))
        resp, data = self.request("/s/{}?dl=1".format(TOKEN_LIMIT))
        self.assertEqual(resp.status, 410)
        self.assertNotIn(b"hello", data)
        resp, _ = self.request("/s/" + TOKEN_LIMIT)
        self.assertEqual(resp.status, 410)

    def test_expired(self):
        resp, _ = self.request("/s/{}?dl=1".format(TOKEN_EXPIRED))
        self.assertEqual(resp.status, 410)
        # Links expire while the server is running.
        self.clock.now += 400 * 86400
        self.links[TOKEN_FILE]["expires"] = int(time.time()) + 3600
        self.write_export()
        resp, _ = self.request("/s/{}?dl=1".format(TOKEN_FILE))
        self.assertEqual(resp.status, 410)

    def test_unknown_and_malformed(self):
        for path in ["/s/" + "Z" * 22, "/s/short", "/", "/s/",
                     "/s/{}/x".format(TOKEN_FILE),
                     "/s/{}/".format(TOKEN_FILE), "/etc/passwd"]:
            resp, _ = self.request(path)
            self.assertEqual(resp.status, 404, path)

    def test_audit_log(self):
        self.request("/s/{}?dl=1".format(TOKEN_FILE))
        self.login(TOKEN_PW, "wrong")
        self.request("/s/{}/?zip=1".format(TOKEN_DIR))
        self.assertIn("[link:admin] share-download: Share:/report.pdf "
                      "(from 127.0.0.1)", self.logs)
        self.assertIn("[link:admin] share-auth-failed: Share:/docs/a.txt "
                      "(from 127.0.0.1)", self.logs)
        self.assertIn("[link:admin] share-download: Share:/docs "
                      "(from 127.0.0.1)", self.logs)
        # Files of a ZIP archive are not logged separately.
        self.assertEqual(len(self.logs), 3)
        with open(self.export_file) as f:
            data = json.load(f)
        data["auditlog"] = False
        with open(self.export_file, "w") as f:
            json.dump(data, f)
        st = os.stat(self.export_file)
        os.utime(self.export_file, ns=(st.st_atime_ns,
                                       st.st_mtime_ns + 5000))
        self.request("/s/{}?dl=1".format(TOKEN_FILE))
        self.assertEqual(len(self.logs), 3)

    def test_robots(self):
        resp, data = self.request("/robots.txt")
        self.assertEqual(resp.status, 200)
        self.assertIn(b"Disallow: /", data)

    def test_type_changed(self):
        # A file link whose path is a folder now.
        resp, _ = self.request("/s/" + TOKEN_TYPE)
        self.assertEqual(resp.status, 404)

    def test_target_replaced_by_symlink(self):
        os.rename(os.path.join(self.root, "report.pdf"),
                  os.path.join(self.root, "report.bak"))
        os.symlink(os.path.join(self.outside, "secret"),
                   os.path.join(self.root, "report.pdf"))
        resp, data = self.request("/s/{}?dl=1".format(TOKEN_FILE))
        self.assertEqual(resp.status, 404)
        self.assertNotIn(b"secret", data)

    def test_methods(self):
        resp, _ = self.request("/s/" + TOKEN_FILE, "PUT")
        self.assertEqual(resp.status, 501)
        resp, _ = self.request("/s/" + TOKEN_FILE, "DELETE")
        self.assertEqual(resp.status, 501)

    def test_export_reloaded(self):
        resp, _ = self.request("/s/" + TOKEN_NEW)
        self.assertEqual(resp.status, 404)
        self.links[TOKEN_NEW] = self.link("docs/a.txt", "file")
        self.write_export()
        resp, data = self.request("/s/{}?dl=1".format(TOKEN_NEW))
        self.assertEqual((resp.status, data), (200, b"hello"))
        del self.links[TOKEN_NEW]
        self.write_export()
        resp, _ = self.request("/s/{}?dl=1".format(TOKEN_NEW))
        self.assertEqual(resp.status, 404)

    # -- passwords ---------------------------------------------------------

    def test_password(self):
        resp, data = self.request("/s/" + TOKEN_PW)
        self.assertEqual(resp.status, 401)
        self.assertIn(b"type=\"password\"", data)
        self.assertNotIn(b"a.txt", data)
        resp, data = self.request("/s/{}?dl=1".format(TOKEN_PW))
        self.assertEqual(resp.status, 401)
        self.assertNotIn(b"hello", data)
        resp = self.login(TOKEN_PW, "wrong")
        self.assertEqual(resp.status, 401)
        resp = self.login(TOKEN_PW)
        self.assertEqual(resp.status, 303)
        cookie = resp.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("Secure", cookie)
        cookie = cookie.split(";")[0]
        resp, data = self.request("/s/{}?dl=1".format(TOKEN_PW),
                                  headers={"Cookie": cookie})
        self.assertEqual((resp.status, data), (200, b"hello"))
        # The session is bound to the link.
        name, value = cookie.split("=", 1)
        self.links[TOKEN_NEW] = self.link("docs/a.txt", "file",
                                          password=pbkdf2(PASSWORD))
        self.write_export()
        other = "{}={}".format(share_server.cookie_name(TOKEN_NEW), value)
        resp, _ = self.request("/s/{}?dl=1".format(TOKEN_NEW),
                               headers={"Cookie": other})
        self.assertEqual(resp.status, 401)
        # Sessions expire.
        self.clock.now += share_server.SESSION_LIFETIME + 1
        resp, _ = self.request("/s/{}?dl=1".format(TOKEN_PW),
                               headers={"Cookie": cookie})
        self.assertEqual(resp.status, 401)

    def test_forged_session(self):
        expires = int(self.clock.now) + 3600
        forged = base64.urlsafe_b64encode(
            expires.to_bytes(8, "big") + b"\0" * 16).decode().rstrip("=")
        for value in [forged, "garbage", "", "A" * 200]:
            resp, _ = self.request(
                "/s/{}?dl=1".format(TOKEN_PW),
                headers={"Cookie": "{}={}".format(
                    share_server.cookie_name(TOKEN_PW), value)})
            self.assertEqual(resp.status, 401, value)

    def test_throttling(self):
        for _ in range(share_server.THROTTLE_PER_ADDRESS):
            self.assertEqual(self.login(TOKEN_PW, "wrong").status, 401)
        # Even the right password is refused now.
        self.assertEqual(self.login(TOKEN_PW).status, 429)
        self.clock.now += share_server.THROTTLE_WINDOW + 1
        self.assertEqual(self.login(TOKEN_PW).status, 303)

    def test_password_body_limit(self):
        resp, _ = self.request(
            "/s/" + TOKEN_PW, "POST", body="password=" + "x" * 5000,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(resp.status, 404)

    def test_php_password_hash(self):
        """The hash written by the RPC (PHP) is verified by the server."""
        php = shutil.which("php")
        if php is None:
            self.skipTest("php is not installed")
        script = (
            "$salt = random_bytes(16); printf('pbkdf2_sha256$%d$%s$%s', "
            "200000, base64_encode($salt), base64_encode(hash_pbkdf2("
            "'sha256', $argv[1], $salt, 200000, 32, true)));")
        encoded = subprocess.check_output([php, "-r", script, PASSWORD],
                                          text=True)
        self.assertTrue(share_server.Broker.check_password(encoded,
                                                           PASSWORD))
        self.assertFalse(share_server.Broker.check_password(encoded, "x"))

    def test_check_password_rejects_bad_hashes(self):
        for encoded in ["", "plain", "md5$1$AA==$AA==",
                        "pbkdf2_sha256$0$AA==$AA==",
                        "pbkdf2_sha256$99999999999$AA==$AA==",
                        "pbkdf2_sha256$1000$!!$AA=="]:
            self.assertFalse(share_server.Broker.check_password(encoded,
                                                                "x"))

    # -- folder links ------------------------------------------------------

    def test_folder_listing(self):
        resp, _ = self.request("/s/" + TOKEN_DIR)
        self.assertEqual(resp.status, 301)
        self.assertEqual(resp.getheader("Location"), TOKEN_DIR + "/")
        resp, data = self.request("/s/{}/".format(TOKEN_DIR))
        self.assertEqual(resp.status, 200)
        text = data.decode()
        self.assertIn("a.txt", text)
        self.assertIn("sub/", text)
        for hidden in [".hidden", "fmpart", "escape", "leak.txt",
                       "alias.txt", "fifo"]:
            self.assertNotIn(hidden, text)
        resp, data = self.request("/s/{}/sub/".format(TOKEN_DIR))
        self.assertEqual(resp.status, 200)
        self.assertIn(b"b.txt", data)
        resp, data = self.request("/s/{}/sub/b.txt?dl=1".format(TOKEN_DIR))
        self.assertEqual((resp.status, data), (200, b"world"))

    def test_folder_hidden_files_setting(self):
        self.write_export(showhidden=True)
        resp, data = self.request("/s/{}/".format(TOKEN_DIR))
        self.assertIn(b".hidden", data)
        self.assertNotIn(b"fmpart", data)
        resp, data = self.request("/s/{}/.hidden?dl=1".format(TOKEN_DIR))
        self.assertEqual((resp.status, data), (200, b"hidden"))
        self.write_export(showhidden=False)
        resp, _ = self.request("/s/{}/.hidden?dl=1".format(TOKEN_DIR))
        self.assertEqual(resp.status, 404)

    def test_folder_traversal(self):
        for path in ["..", "../report.pdf", "%2E%2E/report.pdf",
                     "..%2Freport.pdf", "sub%2Fb.txt", "escape/secret",
                     "leak.txt", "alias.txt", "fifo", ".c.txt.fmpart",
                     "a.txt%00", "./a.txt", "sub//b.txt", "%FF"]:
            resp, data = self.request("/s/{}/{}?dl=1".format(TOKEN_DIR,
                                                             path))
            self.assertIn(resp.status, (404,), path)
            self.assertNotIn(b"secret", data)
            self.assertNotIn(b"%PDF", data)

    def test_share_root_hides_trash(self):
        resp, data = self.request("/s/{}/".format(TOKEN_ROOT))
        self.assertEqual(resp.status, 200)
        self.assertIn(b"docs/", data)
        self.assertNotIn(b".recycle", data)
        self.write_export(showhidden=True)
        resp, data = self.request("/s/{}/".format(TOKEN_ROOT))
        self.assertNotIn(b".recycle", data)
        resp, _ = self.request(
            "/s/{}/.recycle/admin/trashed.txt?dl=1".format(TOKEN_ROOT))
        self.assertEqual(resp.status, 404)

    def test_zip(self):
        resp, data = self.request("/s/{}/?zip=1".format(TOKEN_DIR))
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "application/zip")
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = sorted(zf.namelist())
        self.assertIn("docs/a.txt", names)
        self.assertIn("docs/sub/b.txt", names)
        self.assertIn("docs/sub/", names)
        for name in names:
            for hidden in [".hidden", "fmpart", "escape", "leak", "alias",
                           "fifo"]:
                self.assertNotIn(hidden, name)
        self.assertEqual(zf.read("docs/sub/b.txt"), b"world")
        self.assertEqual(zf.getinfo("docs/photo.jpg").compress_type,
                         zipfile.ZIP_STORED)
        self.assertEqual(zf.getinfo("docs/a.txt").compress_type,
                         zipfile.ZIP_DEFLATED)
        self.assertIsNone(zf.testzip())
        with open(self.state_file) as f:
            self.assertEqual(json.load(f)[TOKEN_DIR]["downloads"], 1)
        # Subfolders can be downloaded as ZIP, too.
        resp, data = self.request("/s/{}/sub/?zip=1".format(TOKEN_DIR))
        self.assertEqual(sorted(zipfile.ZipFile(io.BytesIO(data))
                                .namelist()), ["sub/b.txt"])

    def test_zip_share_root_without_trash(self):
        resp, data = self.request("/s/{}/?zip=1".format(TOKEN_ROOT))
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertTrue(any(n.endswith("report.pdf") for n in names))
        self.assertFalse(any(".recycle" in n for n in names))

    def test_large_folder(self):
        """Listings larger than one message are split into chunks."""
        big = os.path.join(self.root, "docs", "big")
        os.makedirs(big)
        for i in range(3000):
            with open(os.path.join(big, "file-{:05d}-{}.txt".format(
                    i, "x" * 60)), "w") as f:
                f.write(str(i))
        resp, data = self.request("/s/{}/big/".format(TOKEN_DIR))
        self.assertEqual(resp.status, 200)
        self.assertEqual(data.count(b"?dl=1"), 3000)
        resp, data = self.request("/s/{}/big/?zip=1".format(TOKEN_DIR))
        zf = zipfile.ZipFile(io.BytesIO(data))
        self.assertEqual(len(zf.namelist()), 3000)
        self.assertEqual(zf.read("big/file-02999-{}.txt".format("x" * 60)),
                         b"2999")

    def test_names_with_special_characters(self):
        name = "ä ö #?&%\"<b>.txt"
        self.write("docs/" + name, "special")
        resp, data = self.request("/s/{}/".format(TOKEN_DIR))
        self.assertNotIn(b"<b>", data)
        self.assertIn(b"&lt;b&gt;", data)
        quoted = __import__("urllib.parse").parse.quote(name, safe="")
        resp, data = self.request("/s/{}/{}?dl=1".format(TOKEN_DIR, quoted))
        self.assertEqual((resp.status, data), (200, b"special"))
        self.assertIn("filename*=UTF-8''", resp.getheader(
            "Content-Disposition"))

    # -- permissions of the user that created the link ---------------------

    def test_user_permissions(self):
        # The creator is not the owner and in no group: only the "other"
        # permissions apply.
        resp, data = self.request("/s/{}/".format(TOKEN_USER))
        self.assertEqual(resp.status, 200)
        self.assertIn(b"report.pdf", data)
        self.assertNotIn(b"private.txt", data)
        resp, _ = self.request("/s/{}/private.txt?dl=1".format(TOKEN_USER))
        self.assertEqual(resp.status, 404)
        resp, _ = self.request("/s/{}/report.pdf?dl=1".format(TOKEN_USER))
        self.assertEqual(resp.status, 200)
        os.chmod(os.path.join(self.root, "docs"), 0o700)
        resp, _ = self.request("/s/{}/docs/a.txt?dl=1".format(TOKEN_USER))
        self.assertEqual(resp.status, 404)
        resp, data = self.request("/s/{}/".format(TOKEN_USER))
        self.assertNotIn(b"docs/", data)
        resp, data = self.request("/s/{}/?zip=1".format(TOKEN_USER))
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertFalse(any("private" in n or "docs" in n for n in names))
        # The owner may read.
        self.links[TOKEN_USER]["creds"] = {"uid": os.getuid(), "gids": []}
        self.write_export()
        resp, _ = self.request("/s/{}/private.txt?dl=1".format(TOKEN_USER))
        self.assertEqual(resp.status, 200)

    def test_may_access(self):
        class St:
            def __init__(self, mode, uid=1000, gid=100):
                self.st_mode, self.st_uid, self.st_gid = mode, uid, gid

        orig = share_server.read_acl
        try:
            share_server.read_acl = lambda fd: None
            user = {"uid": 2000, "gids": [100]}
            other = {"uid": 2000, "gids": [200]}
            self.assertTrue(share_server.may_access(0, St(0o640), 4, None))
            self.assertTrue(share_server.may_access(0, St(0o640), 4, user))
            self.assertFalse(share_server.may_access(0, St(0o640), 4, other))
            self.assertFalse(share_server.may_access(0, St(0o604, gid=100),
                                                     4, user))
            self.assertTrue(share_server.may_access(
                0, St(0o400, uid=2000), 4, user))
            self.assertFalse(share_server.may_access(
                0, St(0o077, uid=2000), 4, user))
            # ACL: named user, masked; named group; other.
            acl = [(share_server.ACL_USER_OBJ, 7, 0),
                   (share_server.ACL_USER, 7, 3000),
                   (share_server.ACL_GROUP_OBJ, 0, 0),
                   (share_server.ACL_GROUP, 4, 300),
                   (share_server.ACL_MASK, 4, 0),
                   (share_server.ACL_OTHER, 0, 0)]
            share_server.read_acl = lambda fd: acl
            self.assertTrue(share_server.may_access(
                0, St(0o740), 4, {"uid": 3000, "gids": []}))
            self.assertFalse(share_server.may_access(
                0, St(0o740), 2, {"uid": 3000, "gids": []}))
            self.assertTrue(share_server.may_access(
                0, St(0o740), 4, {"uid": 4000, "gids": [300]}))
            self.assertFalse(share_server.may_access(
                0, St(0o740), 4, {"uid": 4000, "gids": [100]}))
            self.assertFalse(share_server.may_access(
                0, St(0o740), 4, {"uid": 4000, "gids": []}))
        finally:
            share_server.read_acl = orig

    def test_read_acl_format(self):
        path = os.path.join(self.root, "report.pdf")
        if shutil.which("setfacl") is None or subprocess.call(
                ["setfacl", "-m", "u:{}:r".format(os.getuid() + 1), path],
                stderr=subprocess.DEVNULL) != 0:
            self.skipTest("ACLs are not supported")
        fd = os.open(path, os.O_RDONLY)
        try:
            acl = share_server.read_acl(fd)
        finally:
            os.close(fd)
        self.assertIn((share_server.ACL_USER, 4, os.getuid() + 1), acl)

    # -- TLS ---------------------------------------------------------------

    def test_tls(self):
        if shutil.which("openssl") is None:
            self.skipTest("openssl is not installed")
        cert = os.path.join(self.tmp, "cert.pem")
        key = os.path.join(self.tmp, "key.pem")
        subprocess.check_call(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "1", "-subj",
             "/CN=localhost"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        self.server.shutdown()
        self.server.server_close()
        self.start_server(share_server.make_tls_context(cert, key))
        ctx = ssl.create_default_context(cafile=cert)
        ctx.check_hostname = False
        resp, data = self.request("/s/{}?dl=1".format(TOKEN_FILE),
                                  context=ctx)
        self.assertEqual((resp.status, data), (200, b"%PDF-1.4"))
        self.assertIsNotNone(resp.getheader("Strict-Transport-Security"))
        resp = None
        conn = http.client.HTTPSConnection("127.0.0.1", self.port,
                                           timeout=10, context=ctx)
        conn.request("POST", "/s/" + TOKEN_PW, body="password=" +
                     __import__("urllib.parse").parse.quote(PASSWORD),
                     headers={"Content-Type":
                              "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        self.assertIn("Secure", resp.getheader("Set-Cookie"))
        conn.close()
        # Plain HTTP is not answered on the TLS port.
        with socket.create_connection(("127.0.0.1", self.port),
                                      timeout=10) as s:
            s.sendall(b"GET /s/" + TOKEN_FILE.encode() + b"?dl=1 HTTP/1.0"
                      b"\r\n\r\n")
            try:
                data = s.recv(4096)
            except ConnectionResetError:
                data = b""
            self.assertNotIn(b"%PDF", data)

    # -- connection limit --------------------------------------------------

    def test_connection_limit(self):
        socks = []
        try:
            for _ in range(share_server.MAX_CONNECTIONS):
                socks.append(socket.create_connection(("127.0.0.1",
                                                       self.port)))
            time.sleep(0.5)
            extra = socket.create_connection(("127.0.0.1", self.port))
            extra.settimeout(5)
            extra.sendall(b"GET /robots.txt HTTP/1.0\r\n\r\n")
            self.assertEqual(extra.recv(100), b"")
            extra.close()
        finally:
            for s in socks:
                s.close()
        time.sleep(0.5)
        resp, _ = self.request("/robots.txt")
        self.assertEqual(resp.status, 200)


if __name__ == "__main__":
    unittest.main()
