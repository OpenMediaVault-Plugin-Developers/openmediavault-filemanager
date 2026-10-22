# openmediavault-filemanager

A **native** file manager for OpenMediaVault 8, built entirely on the
declarative workbench framework — no external application, no iframe. It is
the counter-model to `openmediavault-filebrowser`, which only proxies the
third-party *filebrowser* container.

## What it does

- Lists shared folders, then browses their contents in a standard OMV
  datatable (flat view with a `..` row, or a lazy-loading tree). The current
  location is shown in the breadcrumb.
- Create folders and empty files, rename, copy and move (also between shared
  folders), duplicate (`name (copy).ext`), create relative symbolic links
  within a shared folder, change permissions and owner (optionally
  recursively).
- Edit text files in the code editor. Files are limited by a configurable
  size, binary and non-UTF-8 files are refused, and saving is atomic and
  keeps the owner, mode and ACLs. Saving is refused if the file was changed
  by someone else since it was opened.
- Upload files of any size, download files, and download folders or several
  items as one ZIP archive.
- Download a file from a http:// or https:// URL into the current folder,
  with progress. Addresses in the local network and of the NAS itself are
  refused, also after redirects, and downloads larger than the free space
  are aborted.
- Preview images, PDFs, audio, video and text in a new browser tab; other
  files are downloaded. Clicking a file name does the same, clicking a folder
  name opens it.
- Compress to ZIP or tar.gz and extract archives into a new folder (ZIP,
  tar, tar.gz/bz2/xz/zst, and via bsdtar 7z, RAR, ISO, CAB, CPIO, XAR and
  LZH).
- Disk usage of a folder: the size of every item in it, largest first.
- Properties dialog (type, MIME type, owner, mode, ACLs, recursive size).
- Checksums (MD5, SHA-1, SHA-256, SHA-512) of one or more files.
- Recursive search by name, with wildcards.
- Trash: deleted items go to `.recycle/<user>/<path>` in the shared folder,
  the same layout the Samba recycle bin uses, and can be restored. Deleting
  permanently asks for confirmation. A trash page lists the deleted items of
  all shared folders with their original location, and items older than a
  configurable number of days are deleted automatically once a day.
- New files and folders inherit the owner, group and mode of their parent
  folder instead of being owned by root.
- Audit log of every change in *Diagnostics | System Logs | File Manager*.
- Share links: links to files and folders that can be downloaded without
  logging in, optionally with a password, an expiry date and a maximum
  number of downloads. See below.
- Settings: enable, read-only mode, which shared folders are available,
  hidden files, editor size limit, trash (incl. automatic cleanup), audit
  log and share links.
- Optional access for non-administrative users, based on the shared folder
  privileges (no access / read-only / read-write) configured in OMV. Like
  with SMB, the file system permissions and ACLs apply to them as well.

## Share links

Share links are served by a separate server
(`openmediavault-filemanager-share.service`, Python standard library only)
on its own port, not by the web interface, engined or PHP. It is only
running while share links are enabled in the settings, and is designed to
be safe to expose to the internet:

- It never sees the OMV configuration and cannot call the RPC. The
  FileManager RPC exports only the links that are currently valid, checked
  with the privileges of the user that created them (file manager access,
  shared folder privileges, file system permissions), to
  `/var/lib/openmediavault-filemanager/share-export.json`. The links are
  checked again daily and whenever they or the settings change.
- It is privilege separated: the process that speaks HTTP(S) runs as the
  unprivileged user `omv-fm-share` in an empty chroot without any
  capabilities and cannot open files. A small broker process without
  network access checks every request (link valid, not expired or used up,
  session) and opens the file for it: path components are opened one by one
  with `O_NOFOLLOW` below the shared item, so symlinks and `..` cannot lead
  outside, and for links of non-administrative users the permissions and
  ACLs of that user are checked again on every access.
- Passwords are stored as PBKDF2-SHA256 hashes; wrong passwords are rate
  limited per address and per link. Downloads are sent as attachments with
  a restrictive Content Security Policy and no referrer.
- The systemd unit adds a strict sandbox (read-only file system, no access
  to `/etc/openmediavault`, `/etc/shadow` etc., system call filter).
- Downloads and failed passwords appear in the audit log as
  `[link:<user>] share-download` and `share-auth-failed`.

Use a certificate (HTTPS) when the links are reachable from the internet,
and set the public URL if the server is behind a reverse proxy or a port
forwarding.

## Tests

- `tests/test_share_server.py` tests the share link server without OMV or
  root: `python3 tests/test_share_server.py`.
- `tests/test-rpc.sh` tests all RPC methods and the running share link
  server on an OMV system: `sudo ./tests/test-rpc.sh <sharedfolder>
  [<username>]`.
