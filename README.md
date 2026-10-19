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
  folders), change permissions and owner (optionally recursively).
- Edit text files in the code editor. Files are limited by a configurable
  size, binary and non-UTF-8 files are refused, and saving is atomic and
  keeps the owner, mode and ACLs.
- Upload files of any size, download files, and download folders or several
  items as one ZIP archive.
- Preview images, PDFs, audio, video and text in a new browser tab; other
  files are downloaded. Clicking a file name does the same, clicking a folder
  name opens it.
- Compress to ZIP or tar.gz and extract archives into a new folder.
- Properties dialog (type, MIME type, owner, mode, ACLs, recursive size).
- Recursive search by name, with wildcards.
- Trash: deleted items go to `.recycle/<user>/<path>` in the shared folder,
  the same layout the Samba recycle bin uses, and can be restored. Deleting
  permanently asks for confirmation.
- New files and folders inherit the owner, group and mode of their parent
  folder instead of being owned by root.
- Audit log of every change in *Diagnostics | System Logs | File Manager*.
- Settings: enable, read-only mode, which shared folders are available,
  hidden files, editor size limit, trash and audit log.
- Optional access for non-administrative users, based on the shared folder
  privileges (no access / read-only / read-write) configured in OMV.
