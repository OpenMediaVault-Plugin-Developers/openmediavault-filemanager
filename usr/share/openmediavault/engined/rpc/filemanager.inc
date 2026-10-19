<?php

/**
 * This file is part of OpenMediaVault.
 *
 * @license   https://www.gnu.org/licenses/gpl.html GPL Version 3
 * @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
 * @copyright Copyright (c) 2009-2026 Volker Theile
 *
 * OpenMediaVault is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * OpenMediaVault is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenMediaVault. If not, see <https://www.gnu.org/licenses/>.
 */

namespace Engined\Rpc;

require_once("openmediavault/functions.inc");

/**
 * A native file manager RPC. Browsing is always anchored to a shared
 * folder's root path; every method canonicalises the requested path and
 * asserts it stays inside that root, mirroring the confinement approach
 * used by the core FolderBrowser RPC.
 *
 * Administrators have full access. Non-administrators are only admitted
 * when enabled in the settings, and then only according to the shared
 * folder privileges (no access / read-only / read-write) configured in
 * OMV, the same model the SMB and FTP services use.
 */
class FileManager extends \OMV\Rpc\ServiceAbstract
{
    // Trash location below the shared folder root. This matches the
    // Samba recycle bin default (`.recycle/%U` with `keeptree`), so files
    // deleted here and via SMB end up in the same place.
    const TRASH_DIR = ".recycle";
    // Suffix of partially uploaded files.
    const PART_SUFFIX = ".fmpart";
    // Maximum number of search results.
    const SEARCH_LIMIT = 1000;

    const PERMS_NONE = 0;
    const PERMS_RO = 5;
    const PERMS_RW = 7;

    private $settings = null;
    private $shareCache = [];
    private $userCache = [];
    private $groupCache = [];

    public function getName()
    {
        return "FileManager";
    }

    public function initialize()
    {
        $this->registerMethod("getSettings");
        $this->registerMethod("setSettings");
        $this->registerMethod("enumerateSharedFolders");
        $this->registerMethod("enumerateBrowsableFolders");
        $this->registerMethod("enumerateUsers");
        $this->registerMethod("enumerateGroups");
        $this->registerMethod("getSharedFolderList");
        $this->registerMethod("getLocation");
        $this->registerMethod("getList");
        $this->registerMethod("search");
        $this->registerMethod("mkDir");
        $this->registerMethod("mkFile");
        $this->registerMethod("rename");
        $this->registerMethod("delete");
        $this->registerMethod("restore");
        $this->registerMethod("emptyTrash");
        $this->registerMethod("getFileContent");
        $this->registerMethod("setFileContent");
        $this->registerMethod("download");
        $this->registerMethod("downloadArchive");
        $this->registerMethod("preview");
        $this->registerMethod("uploadChunk");
        $this->registerMethod("transfer");
        $this->registerMethod("chmod");
        $this->registerMethod("chown");
        $this->registerMethod("compress");
        $this->registerMethod("extract");
        $this->registerMethod("getProperties");
    }

    /* ------------------------------------------------------------------
     * Settings
     * ------------------------------------------------------------------ */

    /**
     * Get the plugin settings. Falls back to the defaults if the
     * configuration database has not been populated yet.
     */
    private function settings()
    {
        if (!is_null($this->settings)) {
            return $this->settings;
        }
        $defaults = [
            "enable" => true,
            "readonly" => false,
            "showhidden" => true,
            "maxeditsize" => 2,
            "sharedfolders" => "",
            "usetrash" => true,
            "auditlog" => true,
            "allowusers" => false
        ];
        try {
            $db = \OMV\Config\Database::getInstance();
            $this->settings = array_merge($defaults,
                $db->getAssoc("conf.service.filemanager"));
        } catch (\Exception $e) {
            $this->settings = $defaults;
        }
        return $this->settings;
    }

    private function exposedShares()
    {
        $value = trim(strval($this->settings()['sharedfolders']));
        return ($value === "") ? [] : array_values(array_filter(
            array_map("trim", explode(",", $value))));
    }

    public function getSettings($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $result = $this->settings();
        $result['sharedfolders'] = $this->exposedShares();
        return $result;
    }

    public function setSettings($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $this->validateMethodParams($params,
            "rpc.filemanager.setsettings");
        $params['sharedfolders'] = implode(",", array_filter(
            (array)$params['sharedfolders']));
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.filemanager");
        $object->setAssoc($params);
        $db->set($object);
        $this->settings = null;
        $this->audit($context, "settings", null, null,
            json_encode_safe($params));
        return $this->getSettings([], $context);
    }

    /* ------------------------------------------------------------------
     * Path tokens
     * ------------------------------------------------------------------ */

    /**
     * Encode a shared-folder-relative path into a route-safe token
     * (base64url, no padding). "." (the root) maps to the literal "root"
     * so the workbench YAML can reference it without magic strings.
     */
    private function encodePath($relPath)
    {
        $relPath = $this->normalizeRel($relPath);
        if ($relPath === ".") {
            return "root";
        }
        return rtrim(strtr(base64_encode($relPath), "+/", "-_"), "=");
    }

    private function decodePath($token)
    {
        if ($token === "" || $token === "root") {
            return ".";
        }
        $b64 = strtr($token, "-_", "+/");
        $pad = strlen($b64) % 4;
        if ($pad) {
            $b64 .= str_repeat("=", 4 - $pad);
        }
        $decoded = base64_decode($b64, true);
        if (false === $decoded) {
            throw new \OMV\Exception("Invalid path token.");
        }
        return $this->normalizeRel($decoded);
    }

    private function normalizeRel($relPath)
    {
        $relPath = ltrim(strval($relPath), "/");
        $relPath = preg_replace("#/+#", "/", $relPath);
        $relPath = preg_replace("#^(\./)+#", "", $relPath);
        $relPath = rtrim($relPath, "/");
        return ($relPath === "" || $relPath === ".") ? "." : $relPath;
    }

    /**
     * Split a comma separated list of path tokens.
     */
    private function splitTokens($tokens)
    {
        $result = array_values(array_filter(array_map("trim",
            explode(",", strval($tokens))), "strlen"));
        if (empty($result)) {
            throw new \OMV\Exception("No items selected.");
        }
        return $result;
    }

    private function joinRel($relPath, $name)
    {
        return ($relPath === ".") ? $name : $relPath . "/" . $name;
    }

    /* ------------------------------------------------------------------
     * Access control
     * ------------------------------------------------------------------ */

    private function isAdmin($context)
    {
        return OMV_ROLE_ADMINISTRATOR === ($context['role'] &
            OMV_ROLE_ADMINISTRATOR);
    }

    private function getShare($uuid)
    {
        if (!array_key_exists($uuid, $this->shareCache)) {
            $db = \OMV\Config\Database::getInstance();
            $this->shareCache[$uuid] = $db->getAssoc(
                "conf.system.sharedfolder", $uuid);
        }
        return $this->shareCache[$uuid];
    }

    /**
     * Get the groups a user is member of.
     */
    private function getUserGroups($username)
    {
        $cmd = new \OMV\System\Process("id", ["-Gn", "--",
            escapeshellarg($username)]);
        $cmd->setQuiet(true);
        $cmd->execute($output, $exitStatus);
        if (0 !== $exitStatus || empty($output)) {
            return [];
        }
        return preg_split("/\s+/", trim(implode(" ", $output)));
    }

    /**
     * Get the effective permissions of the caller on a shared folder,
     * derived from the shared folder privileges. An explicit 'no access'
     * for the user or any of its groups always wins, like the Samba
     * `invalid users` semantics OMV generates from the same data.
     */
    private function getSharePerms($uuid, $context)
    {
        if ($this->isAdmin($context)) {
            return self::PERMS_RW;
        }
        $share = $this->getShare($uuid);
        $privileges = array_value($share, "privileges", []);
        $privileges = is_array($privileges) ?
            array_value($privileges, "privilege", []) : [];
        if (!is_array($privileges)) {
            return self::PERMS_NONE;
        }
        // A single privilege may not be wrapped into a list.
        if (array_key_exists("type", $privileges)) {
            $privileges = [$privileges];
        }
        $username = $context['username'];
        $groups = $this->getUserGroups($username);
        $userPerms = null;
        $groupPerms = null;
        foreach ($privileges as $privilege) {
            $perms = intval($privilege['perms']);
            if (($privilege['type'] === "user") &&
                ($privilege['name'] === $username)) {
                $userPerms = $perms;
            } elseif (($privilege['type'] === "group") &&
                in_array($privilege['name'], $groups, true)) {
                if (self::PERMS_NONE === $perms) {
                    return self::PERMS_NONE;
                }
                $groupPerms = max(intval($groupPerms), $perms);
            }
        }
        if (!is_null($userPerms)) {
            return $userPerms;
        }
        return is_null($groupPerms) ? self::PERMS_NONE : $groupPerms;
    }

    /**
     * Assert that the file manager may be used by the caller.
     */
    private function assertEnabled($context)
    {
        $settings = $this->settings();
        if (!boolvalEx($settings['enable'])) {
            throw new \OMV\Exception("The file manager is disabled.");
        }
        if (!$this->isAdmin($context) &&
            !boolvalEx($settings['allowusers'])) {
            throw new \OMV\Exception("The file manager is not available " .
                "for non-administrative users.");
        }
    }

    /**
     * Assert the caller may read (or write) the given shared folder.
     */
    private function assertShareAccess($uuid, $context, $write = false)
    {
        $this->assertEnabled($context);
        $exposed = $this->exposedShares();
        if (!empty($exposed) && !in_array($uuid, $exposed, true)) {
            throw new \OMV\Exception("The shared folder is not available " .
                "in the file manager.");
        }
        $perms = $this->getSharePerms($uuid, $context);
        if ($perms < self::PERMS_RO) {
            throw new \OMV\Exception("You do not have access to this " .
                "shared folder.");
        }
        if ($write) {
            if (boolvalEx($this->settings()['readonly'])) {
                throw new \OMV\Exception("The file manager is in " .
                    "read-only mode.");
            }
            if ($perms < self::PERMS_RW) {
                throw new \OMV\Exception("You only have read access to " .
                    "this shared folder.");
            }
        }
    }

    private function assertAdmin($context)
    {
        if (!$this->isAdmin($context)) {
            throw new \OMV\Exception("This operation requires " .
                "administrative privileges.");
        }
    }

    /**
     * Resolve a shared folder UUID + relative path to an absolute,
     * canonicalised path and guarantee it stays inside the shared folder.
     * Methods that modify the file system must set $write, which is
     * refused for shared folders located at the OS root, e.g. created
     * via the sharerootfs plugin, to prevent damaging the system.
     *
     * If $follow is TRUE, a symlink is resolved to its target (which
     * must be inside the shared folder, too). Otherwise only the parent
     * directory is canonicalised, so the path addresses the directory
     * entry itself; use this for operations that act on the entry, e.g.
     * delete, rename or move, so a symlink is never confused with the
     * file or directory it points to.
     * @return array [rootPath, relPath, absPath]
     */
    private function resolveRel($uuid, $relPath, $context, $write = false,
        $follow = true)
    {
        $this->assertShareAccess($uuid, $context, $write);
        $relPath = $this->normalizeRel($relPath);
        // Defence in depth: reject two-dot path components and NUL
        // bytes before touching the fs.
        if ((1 == preg_match("#(^|/)\.\.(/|$)#", $relPath)) ||
            (false !== strpos($relPath, "\0"))) {
            throw new \OMV\Exception(
                "The path contains forbidden two-dot symbols.");
        }
        $rootPath = \OMV\Rpc\Rpc::call("ShareMgmt", "getPath", [
            "uuid" => $uuid
        ], $this->getAdminContext());
        $rootReal = realpath($rootPath);
        if (false === $rootReal) {
            throw new \OMV\Exception(
                "The shared folder path '%s' does not exist.", $rootPath);
        }
        if ($write && ($rootReal === DIRECTORY_SEPARATOR)) {
            throw new \OMV\Exception(
                "Shared folders located at the root of the operating " .
                "system are read-only.");
        }
        if ($relPath === ".") {
            return [$rootReal, $relPath, $rootReal];
        }
        $absPath = build_path(DIRECTORY_SEPARATOR, $rootReal, $relPath);
        $canon = $follow ? realpath($absPath) : false;
        if (false === $canon) {
            // Canonicalise the parent so non-existent leaf names
            // (mkdir/rename targets) and symlinks still resolve.
            $parent = realpath(dirname($absPath));
            if (false === $parent) {
                throw new \OMV\Exception("The directory '%s' does not " .
                    "exist.", dirname($relPath));
            }
            $canon = build_path(DIRECTORY_SEPARATOR, $parent,
                basename($absPath));
        }
        // Note, the root path is '/' for shared folders located at the
        // OS root, so do not simply append a separator.
        $prefix = rtrim($rootReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (($canon !== $rootReal) && (0 !== strpos($canon, $prefix))) {
            throw new \OMV\Exception(
                "The resolved path escapes the shared folder root.");
        }
        return [$rootReal, $relPath, $canon];
    }

    private function resolve($uuid, $token, $context, $write = false,
        $follow = true)
    {
        return $this->resolveRel($uuid, $this->decodePath($token),
            $context, $write, $follow);
    }

    /**
     * Get the path relative to the shared folder root.
     */
    private function relOf($rootReal, $absPath)
    {
        if ($absPath === $rootReal) {
            return ".";
        }
        $prefix = rtrim($rootReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        return $this->normalizeRel(substr($absPath, strlen($prefix)));
    }

    private function validateName($name)
    {
        $name = strval($name);
        if (($name === "") || ($name === ".") || ($name === "..") ||
            (false !== strpos($name, "/")) ||
            (false !== strpos($name, "\0")) || (strlen($name) > 255)) {
            throw new \OMV\Exception("Invalid name '%s'.", $name);
        }
        return $name;
    }

    /* ------------------------------------------------------------------
     * Helpers
     * ------------------------------------------------------------------ */

    /**
     * Write an audit log entry to the journal (identifier
     * `omv-filemanager`), shown in Diagnostics | System Logs.
     */
    private function audit($context, $action, $uuid, $relPath, $extra = "")
    {
        if (!boolvalEx($this->settings()['auditlog'])) {
            return;
        }
        $location = "";
        if (!is_null($uuid)) {
            try {
                $location = $this->getShare($uuid)['name'];
            } catch (\Exception $e) {
                $location = $uuid;
            }
            if (!is_null($relPath)) {
                $location .= ":/" . (($relPath === ".") ? "" : $relPath);
            }
        }
        $message = sprintf("[%s] %s: %s", $context['username'], $action,
            trim($location . " " . $extra));
        openlog("omv-filemanager", LOG_PID, LOG_USER);
        syslog(LOG_NOTICE, $message);
        closelog();
    }

    private function userName($uid)
    {
        if (!array_key_exists($uid, $this->userCache)) {
            $info = posix_getpwuid($uid);
            $this->userCache[$uid] = (false === $info) ? strval($uid) :
                $info['name'];
        }
        return $this->userCache[$uid];
    }

    private function groupName($gid)
    {
        if (!array_key_exists($gid, $this->groupCache)) {
            $info = posix_getgrgid($gid);
            $this->groupCache[$gid] = (false === $info) ? strval($gid) :
                $info['name'];
        }
        return $this->groupCache[$gid];
    }

    private function hasDefaultAcl($dir)
    {
        $cmd = new \OMV\System\Process("getfacl", ["--omit-header",
            "--default", "--absolute-names", "--",
            escapeshellarg($dir)]);
        $cmd->setQuiet(true);
        $cmd->execute($output, $exitStatus);
        return (0 === $exitStatus) && !empty(array_filter($output,
            "strlen"));
    }

    /**
     * Get the owner of new files and directories: the owner/group of
     * the parent directory, or the calling user for non-administrators.
     * @return array [uid, gid]
     */
    private function newOwner($parentDir, $context)
    {
        $stat = stat($parentDir);
        $uid = $stat['uid'];
        if (!$this->isAdmin($context)) {
            $info = posix_getpwnam($context['username']);
            if (false !== $info) {
                $uid = $info['uid'];
            }
        }
        return [$uid, $stat['gid']];
    }

    /**
     * Give a newly created file or directory the ownership of its parent
     * directory and a matching mode, instead of `root:root`, so it stays
     * accessible via SMB/NFS. If the parent carries a default ACL, the
     * kernel has already applied it, so the mode is left untouched.
     */
    private function inheritOwnership($path, $context, $recursive = false)
    {
        $parentDir = dirname($path);
        list($uid, $gid) = $this->newOwner($parentDir, $context);
        if ($recursive) {
            // Never dereference symlinks, e.g. from an extracted archive.
            $cmd = new \OMV\System\Process("chown", ["-R", "-h", "-P",
                sprintf("%d:%d", $uid, $gid), "--",
                escapeshellarg($path)]);
            $cmd->setQuiet(true);
            $cmd->execute();
        } else {
            @lchown($path, $uid);
            @lchgrp($path, $gid);
        }
        if (is_link($path) || $this->hasDefaultAcl($parentDir)) {
            return;
        }
        $parentMode = fileperms($parentDir) & 07777;
        if (is_dir($path)) {
            @chmod($path, $parentMode);
        } elseif (!$recursive) {
            @chmod($path, $parentMode & 0666);
        }
    }

    /**
     * Create a directory and its missing parents inside a shared folder.
     * Each created level inherits the ownership of its parent, so e.g.
     * Samba can still create its own `.recycle/<user>` folders.
     */
    private function mkdirInherit($rootReal, $relPath, $context)
    {
        $path = $rootReal;
        foreach (explode("/", $this->normalizeRel($relPath)) as $name) {
            if ($name === ".") {
                continue;
            }
            $path = build_path(DIRECTORY_SEPARATOR, $path, $name);
            if (is_link($path)) {
                throw new \OMV\Exception("'%s' is a symbolic link.",
                    $this->relOf($rootReal, $path));
            }
            if (is_dir($path)) {
                continue;
            }
            if (!mkdir($path, 0755)) {
                throw new \OMV\Exception("Failed to create the folder '%s'.",
                    $this->relOf($rootReal, $path));
            }
            $this->inheritOwnership($path, $context);
        }
        return $path;
    }

    private function uniquePath($path, $suffixFmt = " (%d)")
    {
        if (!file_exists($path) && !is_link($path)) {
            return $path;
        }
        for ($i = 2; $i < 10000; $i++) {
            $candidate = $path . sprintf($suffixFmt, $i);
            if (!file_exists($candidate) && !is_link($candidate)) {
                return $candidate;
            }
        }
        throw new \OMV\Exception("Failed to find a free name for '%s'.",
            basename($path));
    }

    private function trashRoot($context)
    {
        // Mirror the Samba layout `.recycle/<username>`.
        return self::TRASH_DIR . "/" . $context['username'];
    }

    private function isInTrash($relPath)
    {
        return ($relPath === self::TRASH_DIR) ||
            (0 === strpos($relPath, self::TRASH_DIR . "/"));
    }

    private function extOf($name)
    {
        $lower = strtolower($name);
        foreach (["tar.gz", "tar.bz2", "tar.xz", "tar.zst"] as $ext) {
            if (str_ends_with($lower, "." . $ext)) {
                return $ext;
            }
        }
        return strtolower(pathinfo($name, PATHINFO_EXTENSION));
    }

    private function isArchive($name)
    {
        return in_array($this->extOf($name), ["zip", "tar", "tar.gz",
            "tgz", "tar.bz2", "tbz", "tbz2", "tar.xz", "txz", "tar.zst",
            "tzst"], true);
    }

    /**
     * Map a file to a preview kind by extension (cheap enough for the
     * listing). The real content type is checked again by preview().
     */
    private function previewKind($name)
    {
        $ext = $this->extOf($name);
        $kinds = [
            "image" => ["png", "jpg", "jpeg", "gif", "webp", "bmp",
                "avif", "ico"],
            "video" => ["mp4", "m4v", "webm", "ogv", "mov"],
            "audio" => ["mp3", "ogg", "oga", "opus", "wav", "flac", "m4a",
                "aac"],
            "pdf" => ["pdf"],
            "text" => ["txt", "log", "md", "csv", "tsv", "json", "yaml",
                "yml", "xml", "ini", "conf", "cfg", "sh", "py", "js", "ts",
                "php", "c", "h", "cpp", "go", "rs", "java", "nfo", "srt",
                "sub", "toml", "env", "sql", "css", "html", "htm", "svg"]
        ];
        foreach ($kinds as $kind => $exts) {
            if (in_array($ext, $exts, true)) {
                return $kind;
            }
        }
        return "";
    }

    /**
     * Build a listing row for a directory entry.
     * @param route The route ("browse" or "open") that folder links use.
     *   Linking to the other of the two folder routes than the one
     *   currently shown makes the workbench rebuild the page, see
     *   getList().
     */
    private function buildRow($uuid, $absPath, $relPath, $dirToken,
        $route = "browse")
    {
        $maxEdit = intval($this->settings()['maxeditsize']) * 1024 * 1024;
        $name = basename($absPath);
        $stat = lstat($absPath);
        $isLink = is_link($absPath);
        $link = $isLink ? strval(@readlink($absPath)) : "";
        // Use the metadata of the link target if it exists, otherwise
        // the metadata of the (broken) link itself.
        if ($isLink && file_exists($absPath)) {
            $stat = stat($absPath);
        }
        $isDir = is_dir($absPath);
        $broken = $isLink && !file_exists($absPath);
        $size = $isDir ? -1 : ($broken ? -1 : $stat['size']);
        return [
            "uuid" => $uuid,
            "route" => $route,
            "name" => $name,
            "type" => $isDir ? "dir" : ($broken ? "brokenlink" : "file"),
            "size" => $size,
            "mtime" => $stat['mtime'],
            "mode" => substr(sprintf("%o", $stat['mode']), -4),
            "owner" => $this->userName($stat['uid']),
            "group" => $this->groupName($stat['gid']),
            "link" => $link,
            "path" => $this->encodePath($relPath),
            "dirpath" => $dirToken,
            "location" => "/" . (($relPath === ".") ? "" :
                ((dirname($relPath) === ".") ? "" : dirname($relPath))),
            "editable" => !$isDir && !$broken && ($size <= $maxEdit),
            "preview" => (!$isDir && !$broken) ? $this->previewKind($name) :
                "",
            "archive" => !$isDir && !$broken && $this->isArchive($name),
            "trashed" => $this->isInTrash($relPath) &&
                (substr_count($relPath, "/") >= 2)
        ];
    }

    /**
     * Make a file readable for the web server process that streams
     * downloads (download.php runs as the unprivileged WebGUI user and
     * can only read world-readable files). Files that are not readable
     * are copied to a temporary file owned by the WebGUI user.
     * @return array [filepath, unlink]
     */
    private function prepareDownloadFile($file)
    {
        $readable = (fileperms($file) & 0004) !== 0;
        for ($dir = dirname($file); $readable && ($dir !== "/");
            $dir = dirname($dir)) {
            $readable = (fileperms($dir) & 0001) !== 0;
        }
        if ($readable) {
            return [$file, false];
        }
        $tmpDir = sys_get_temp_dir();
        $size = filesize($file);
        $free = disk_free_space($tmpDir);
        if ((false !== $free) && ($size > ($free / 2))) {
            throw new \OMV\Exception("The file '%s' is not readable by " .
                "the web server and too large to be staged in '%s'. Grant " .
                "read access to others to download it.", basename($file),
                $tmpDir);
        }
        $tmpFile = tempnam($tmpDir, "filemanager-");
        if (!copy($file, $tmpFile)) {
            @unlink($tmpFile);
            throw new \OMV\Exception("Failed to stage '%s' for download.",
                basename($file));
        }
        $this->chownToWebgui($tmpFile);
        return [$tmpFile, true];
    }

    private function chownToWebgui($file)
    {
        $user = \OMV\Environment::get("OMV_WEBGUI_FILE_OWNERGROUP_NAME",
            "openmediavault-webgui");
        @chmod($file, 0600);
        @chown($file, $user);
        @chgrp($file, $user);
    }

    /* ------------------------------------------------------------------
     * Enumerations
     * ------------------------------------------------------------------ */

    /**
     * All shared folders (for the settings page).
     */
    public function enumerateSharedFolders($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $folders = \OMV\Rpc\Rpc::call("ShareMgmt", "enumerateSharedFolders",
            [], $context);
        $result = [];
        foreach ($folders as $folder) {
            $result[] = [
                "uuid" => $folder['uuid'],
                "name" => $folder['name']
            ];
        }
        return $result;
    }

    /**
     * The shared folders the caller may browse (for selection lists).
     */
    public function enumerateBrowsableFolders($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $result = $this->getSharedFolderList([
            "start" => 0,
            "limit" => -1,
            "sortfield" => "name",
            "sortdir" => "asc"
        ], $context);
        return array_map(function ($folder) {
            return [
                "uuid" => $folder['uuid'],
                "name" => $folder['name']
            ];
        }, $result['data']);
    }

    public function enumerateUsers($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        return $this->getentNames("passwd");
    }

    public function enumerateGroups($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        return $this->getentNames("group");
    }

    /**
     * List users or groups via getent: root, the regular accounts
     * (id >= 1000) and the `users` group, skipping `nobody`/`nogroup`.
     */
    private function getentNames($database)
    {
        $cmd = new \OMV\System\Process("getent", $database);
        $cmd->execute($output);
        $result = [];
        foreach ($output as $line) {
            $parts = explode(":", $line);
            if (count($parts) < 3) {
                continue;
            }
            $id = intval($parts[2]);
            if (($id === 0) || ($id === 100) ||
                (($id >= 1000) && ($id < 65534))) {
                $result[] = ["name" => $parts[0]];
            }
        }
        usort($result, function ($a, $b) {
            return strnatcasecmp($a['name'], $b['name']);
        });
        return $result;
    }

    /* ------------------------------------------------------------------
     * Browsing
     * ------------------------------------------------------------------ */

    /**
     * List the shared folders the caller may browse.
     */
    public function getSharedFolderList($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.common.getlist");
        $this->assertEnabled($context);
        $exposed = $this->exposedShares();
        $folders = \OMV\Rpc\Rpc::call("ShareMgmt", "enumerateSharedFolders",
            [], $this->getAdminContext());
        $result = [];
        foreach ($folders as $folder) {
            if (!empty($exposed) && !in_array($folder['uuid'], $exposed,
                true)) {
                continue;
            }
            $perms = $this->getSharePerms($folder['uuid'], $context);
            if ($perms < self::PERMS_RO) {
                continue;
            }
            if (boolvalEx($this->settings()['readonly'])) {
                $perms = self::PERMS_RO;
            }
            $result[] = [
                "uuid" => $folder['uuid'],
                "name" => $folder['name'],
                "comment" => array_value($folder, "comment", ""),
                "access" => ($perms === self::PERMS_RW) ? "rw" : "ro",
                "path" => "root",
                "trashpath" => $this->encodePath(self::TRASH_DIR)
            ];
        }
        return $this->applyFilter($result, $params['start'],
            $params['limit'], $params['sortfield'], $params['sortdir']);
    }

    /**
     * Get the human readable location of a path token. Used by the
     * route breadcrumb.
     */
    public function getLocation($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.path");
        list($rootReal, $relPath, $dir) = $this->resolve(
            $params['uuid'], $params['path'], $context);
        return [
            "sharename" => $this->getShare($params['uuid'])['name'],
            "location" => "/" . (($relPath === ".") ? "" : $relPath)
        ];
    }

    /**
     * List the contents of a directory inside a shared folder.
     */
    public function getList($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.getlist");
        list($rootReal, $relPath, $dir) = $this->resolve(
            $params['uuid'], $params['path'], $context);
        $showHidden = boolvalEx($this->settings()['showhidden']) ||
            $this->isInTrash($relPath);
        $dirToken = $this->encodePath($relPath);
        // The workbench reuses the page when navigating between two URLs
        // of the same route, so the folder would not be reloaded. Folder
        // links therefore always point to the other one of the two
        // folder routes.
        $route = boolvalEx(array_value($params, "altroute", false)) ?
            "browse" : "open";
        $result = [];
        // Inject a parent ("..") entry so descending/ascending share one
        // "Open" action in the datatable. At the top level it leads back
        // to the list of shared folders, which is marked by an empty path.
        $parentToken = ($relPath === ".") ? "" :
            $this->encodePath(dirname($relPath));
        $result[] = [
            "uuid" => $params['uuid'],
            "route" => $route,
            "name" => "..",
            "type" => "parentdir",
            "size" => -1,
            "mtime" => 0,
            "mode" => "",
            "owner" => "",
            "group" => "",
            "link" => "",
            "path" => $parentToken,
            "dirpath" => $dirToken,
            "location" => "",
            "editable" => false,
            "preview" => "",
            "archive" => false,
            "trashed" => false
        ];
        if (is_dir($dir)) {
            foreach (new \DirectoryIterator($dir) as $item) {
                if ($item->isDot()) {
                    continue;
                }
                $name = $item->getFilename();
                if (!$showHidden && ($name[0] === ".")) {
                    continue;
                }
                // Hide partial uploads.
                if (str_ends_with($name, self::PART_SUFFIX)) {
                    continue;
                }
                $result[] = $this->buildRow($params['uuid'],
                    $item->getPathname(), $this->joinRel($relPath, $name),
                    $dirToken, $route);
            }
        }
        return $this->applyFilter($result, $params['start'],
            $params['limit'], $params['sortfield'], $params['sortdir']);
    }

    /**
     * Recursively search for files and directories by name.
     */
    public function search($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.search");
        list($rootReal, $relPath, $dir) = $this->resolve(
            $params['uuid'], $params['path'], $context);
        $query = trim(strval($params['query']));
        if ($query === "") {
            return $this->applyFilter([], $params['start'],
                $params['limit'], $params['sortfield'], $params['sortdir']);
        }
        $pattern = (strpbrk($query, "*?[") === false) ?
            "*" . $query . "*" : $query;
        $cmdArgs = [escapeshellarg($dir), "-xdev", "-mindepth", "1"];
        if (!boolvalEx($this->settings()['showhidden'])) {
            $cmdArgs = array_merge($cmdArgs, ["-name", "'.*'", "-prune",
                "-o"]);
        }
        $cmdArgs = array_merge($cmdArgs, ["-iname", escapeshellarg($pattern),
            "-print0", "|", "head", "-z", "-n", self::SEARCH_LIMIT]);
        $cmd = new \OMV\System\Process("find", $cmdArgs);
        $cmd->setQuiet(true);
        $cmd->execute($output);
        $result = [];
        foreach (explode("\0", implode("\n", $output)) as $absPath) {
            if (($absPath === "") || (!file_exists($absPath) &&
                !is_link($absPath))) {
                continue;
            }
            $childRel = $this->relOf($rootReal, $absPath);
            if (str_ends_with($childRel, self::PART_SUFFIX)) {
                continue;
            }
            $result[] = $this->buildRow($params['uuid'], $absPath,
                $childRel, $this->encodePath(dirname($childRel)));
        }
        return $this->applyFilter($result, $params['start'],
            $params['limit'], $params['sortfield'], $params['sortdir']);
    }

    /* ------------------------------------------------------------------
     * Create / rename / delete
     * ------------------------------------------------------------------ */

    public function mkDir($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.mkdir");
        list($rootReal, $relPath, $dir) = $this->resolve(
            $params['uuid'], $params['path'], $context, true);
        $name = $this->validateName($params['name']);
        $target = build_path(DIRECTORY_SEPARATOR, $dir, $name);
        if (file_exists($target) || is_link($target)) {
            throw new \OMV\Exception("'%s' already exists.", $name);
        }
        if (!mkdir($target, 0755)) {
            throw new \OMV\Exception("Failed to create directory '%s'.",
                $name);
        }
        $this->inheritOwnership($target, $context);
        $this->audit($context, "mkdir", $params['uuid'],
            $this->joinRel($relPath, $name));
    }

    public function mkFile($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.mkdir");
        list($rootReal, $relPath, $dir) = $this->resolve(
            $params['uuid'], $params['path'], $context, true);
        $name = $this->validateName($params['name']);
        $target = build_path(DIRECTORY_SEPARATOR, $dir, $name);
        $fh = @fopen($target, "x");
        if (false === $fh) {
            throw new \OMV\Exception(file_exists($target) ?
                "'%s' already exists." : "Failed to create file '%s'.",
                $name);
        }
        fclose($fh);
        $this->inheritOwnership($target, $context);
        $this->audit($context, "mkfile", $params['uuid'],
            $this->joinRel($relPath, $name));
    }

    public function rename($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.rename");
        list($rootReal, $relPath, $src) = $this->resolve(
            $params['uuid'], $params['path'], $context, true, false);
        if ($src === $rootReal) {
            throw new \OMV\Exception("The shared folder root cannot be "
                . "renamed.");
        }
        $name = $this->validateName($params['name']);
        $target = build_path(DIRECTORY_SEPARATOR, dirname($src), $name);
        if (file_exists($target) || is_link($target)) {
            throw new \OMV\Exception("The target already exists.");
        }
        if (!rename($src, $target)) {
            throw new \OMV\Exception("Failed to rename '%s'.",
                basename($src));
        }
        $this->audit($context, "rename", $params['uuid'], $relPath,
            "-> " . $name);
    }

    private function removeRecursive($path)
    {
        // Recursively remove the file or directory (mirrors ShareMgmt).
        // Do not descend into other file systems, e.g. data disks
        // mounted below the directory to be removed.
        $cmd = new \OMV\System\Process("rm", ["-f", "-r",
            "--one-file-system", "--", escapeshellarg($path)]);
        $cmd->setRedirect2to1();
        $cmd->execute();
    }

    private function moveEntry($src, $dst)
    {
        if (@rename($src, $dst)) {
            return;
        }
        // Fall back to mv, e.g. when crossing file systems.
        $cmd = new \OMV\System\Process("mv", ["-T", "--",
            escapeshellarg($src), escapeshellarg($dst)]);
        $cmd->setRedirect2to1();
        $cmd->execute();
    }

    /**
     * Delete a file or directory. Items are moved to the shared folder
     * trash unless the trash is disabled, `permanent` is set, or they
     * are already in the trash.
     */
    public function delete($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.delete");
        list($rootReal, $relPath, $path) = $this->resolve(
            $params['uuid'], $params['path'], $context, true, false);
        if ($path === $rootReal) {
            throw new \OMV\Exception("The shared folder root cannot be "
                . "deleted.");
        }
        $permanent = boolvalEx(array_value($params, "permanent", false));
        if (!$permanent && boolvalEx($this->settings()['usetrash']) &&
            !$this->isInTrash($relPath)) {
            $trashRel = $this->trashRoot($context) . "/" . $relPath;
            $trashParent = $this->mkdirInherit($rootReal,
                dirname($trashRel), $context);
            $trashPath = $this->uniquePath(build_path(DIRECTORY_SEPARATOR,
                $trashParent, basename($trashRel)), ".~%d~");
            $this->moveEntry($path, $trashPath);
            // Refresh the time stamp so the trash can be cleaned up by
            // age, like the Samba `recycle:touch` option.
            @touch($trashPath);
            $this->audit($context, "trash", $params['uuid'], $relPath);
            return;
        }
        $this->removeRecursive($path);
        $this->audit($context, "delete", $params['uuid'], $relPath);
    }

    /**
     * Restore an item from the trash to its original location.
     */
    public function restore($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.path");
        list($rootReal, $relPath, $path) = $this->resolve(
            $params['uuid'], $params['path'], $context, true, false);
        // Strip `.recycle/<user>/` and a collision suffix.
        $parts = explode("/", $relPath, 3);
        if (!$this->isInTrash($relPath) || (count($parts) < 3)) {
            throw new \OMV\Exception("The item is not in the trash.");
        }
        $origRel = preg_replace('/\.~\d+~$/', "", $parts[2]);
        // Recreate missing parent folders. mkdirInherit() refuses to
        // descend through symlinks, so the target stays inside the root.
        $target = build_path(DIRECTORY_SEPARATOR, $this->mkdirInherit(
            $rootReal, dirname($origRel), $context), basename($origRel));
        if (file_exists($target) || is_link($target)) {
            throw new \OMV\Exception("'/%s' already exists.", $origRel);
        }
        $this->moveEntry($path, $target);
        $this->audit($context, "restore", $params['uuid'], $origRel);
    }

    /**
     * Empty the trash of a shared folder. Administrators empty the whole
     * trash, users only their own.
     */
    public function emptyTrash($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.uuid");
        $trashRel = $this->isAdmin($context) ? self::TRASH_DIR :
            $this->trashRoot($context);
        list($rootReal, $relPath, $path) = $this->resolveRel(
            $params['uuid'], $trashRel, $context, true, false);
        if (is_link($path) || !is_dir($path)) {
            return;
        }
        foreach (new \DirectoryIterator($path) as $item) {
            if (!$item->isDot()) {
                $this->removeRecursive($item->getPathname());
            }
        }
        $this->audit($context, "emptytrash", $params['uuid'], $relPath);
    }

    /* ------------------------------------------------------------------
     * Editor
     * ------------------------------------------------------------------ */

    private function looksBinary($file)
    {
        $fh = fopen($file, "rb");
        if (false === $fh) {
            throw new \OMV\Exception("Failed to open '%s'.",
                basename($file));
        }
        $chunk = fread($fh, 8192);
        fclose($fh);
        return (false !== strpos(strval($chunk), "\0"));
    }

    public function getFileContent($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.path");
        list($rootReal, $relPath, $file) = $this->resolve(
            $params['uuid'], $params['path'], $context);
        if (!is_file($file)) {
            throw new \OMV\Exception("The file does not exist.");
        }
        $maxSize = intval($this->settings()['maxeditsize']);
        if (filesize($file) > ($maxSize * 1024 * 1024)) {
            throw new \OMV\Exception("The file is larger than %d MiB and " .
                "cannot be opened in the editor. Download it instead.",
                $maxSize);
        }
        if ($this->looksBinary($file)) {
            throw new \OMV\Exception("'%s' is a binary file and cannot be " .
                "opened in the editor.", basename($file));
        }
        $content = file_get_contents($file);
        if (!mb_check_encoding($content, "UTF-8")) {
            throw new \OMV\Exception("'%s' is not UTF-8 encoded and " .
                "cannot be opened in the editor.", basename($file));
        }
        return [
            "uuid" => $params['uuid'],
            "path" => $params['path'],
            "name" => basename($file),
            "location" => "/" . $relPath,
            "content" => $content
        ];
    }

    /**
     * Save a file atomically: write a temporary file next to it, copy the
     * owner, mode and ACLs, then rename it over the original. Files with
     * multiple hard links are written in place to keep the links intact.
     */
    public function setFileContent($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.setcontent");
        list($rootReal, $relPath, $file) = $this->resolve(
            $params['uuid'], $params['path'], $context, true);
        if (!is_file($file)) {
            throw new \OMV\Exception("The file does not exist.");
        }
        clearstatcache(true, $file);
        $stat = stat($file);
        if ($stat['nlink'] > 1) {
            if (false === file_put_contents($file, $params['content'],
                LOCK_EX)) {
                throw new \OMV\Exception("Failed to write '%s'.",
                    basename($file));
            }
        } else {
            $tmpFile = tempnam(dirname($file), "." . basename($file) .
                ".");
            if (false === $tmpFile) {
                throw new \OMV\Exception("Failed to create a temporary " .
                    "file next to '%s'.", basename($file));
            }
            try {
                if (false === file_put_contents($tmpFile,
                    $params['content'])) {
                    throw new \OMV\Exception("Failed to write '%s'.",
                        basename($file));
                }
                chown($tmpFile, $stat['uid']);
                chgrp($tmpFile, $stat['gid']);
                chmod($tmpFile, $stat['mode'] & 07777);
                // Copy the access ACLs, if any (best effort).
                $cmd = new \OMV\System\Process(sprintf(
                    "getfacl --absolute-names -- %s | setfacl " .
                    "--set-file=- -- %s", escapeshellarg($file),
                    escapeshellarg($tmpFile)));
                $cmd->setQuiet(true);
                $cmd->execute();
                if (!rename($tmpFile, $file)) {
                    throw new \OMV\Exception("Failed to replace '%s'.",
                        basename($file));
                }
            } catch (\Exception $e) {
                @unlink($tmpFile);
                throw $e;
            }
        }
        $this->audit($context, "edit", $params['uuid'], $relPath);
    }

    /* ------------------------------------------------------------------
     * Download / preview / upload
     * ------------------------------------------------------------------ */

    /**
     * Stream a file to the browser. Invoked through download.php, e.g.
     *   download.php?service=FileManager&method=download&params={...}
     * The returned structure is the contract download.php expects.
     * Directories are sent as ZIP archive.
     */
    public function download($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.path");
        list($rootReal, $relPath, $file) = $this->resolve(
            $params['uuid'], $params['path'], $context);
        if (is_dir($file)) {
            return $this->downloadArchive([
                "uuid" => $params['uuid'],
                "paths" => $params['path']
            ], $context);
        }
        if (!is_file($file)) {
            throw new \OMV\Exception("The file does not exist.");
        }
        list($filePath, $unlink) = $this->prepareDownloadFile($file);
        $this->audit($context, "download", $params['uuid'], $relPath);
        return [
            "filename" => basename($file),
            "filepath" => $filePath,
            "headers" => [
                "Content-Type" => "application/octet-stream"
            ],
            "unlink" => $unlink
        ];
    }

    /**
     * Download several files and/or directories as one ZIP archive.
     */
    public function downloadArchive($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.paths");
        $items = [];
        foreach ($this->splitTokens($params['paths']) as $token) {
            list($rootReal, $relPath, $path) = $this->resolve(
                $params['uuid'], $token, $context);
            if (!file_exists($path)) {
                throw new \OMV\Exception("'%s' does not exist.", $relPath);
            }
            $items[] = [$relPath, $path];
        }
        $name = (count($items) === 1) ? (($items[0][0] === ".") ?
            $this->getShare($params['uuid'])['name'] :
            basename($items[0][1])) : "download";
        // The archive is staged in the temporary directory, which is
        // usually a RAM disk, so refuse archives that would not fit.
        $cmdArgs = ["-s", "-b", "-c", "-x", "--"];
        foreach ($items as $item) {
            $cmdArgs[] = escapeshellarg($item[1]);
        }
        $cmd = new \OMV\System\Process("du", $cmdArgs);
        $cmd->setQuiet(true);
        $total = intval(strval($cmd->execute()));
        $free = disk_free_space(sys_get_temp_dir());
        if ((false !== $free) && ($total > ($free / 2))) {
            throw new \OMV\Exception("The selection (%s) is too large to " .
                "be downloaded as one archive. Create an archive with " .
                "'Compress' and download that file instead.",
                binary_format($total));
        }
        $tmpFile = tempnam(sys_get_temp_dir(), "filemanager-");
        try {
            $this->writeZip($tmpFile, array_column($items, 1));
        } catch (\Exception $e) {
            @unlink($tmpFile);
            throw $e;
        }
        $this->chownToWebgui($tmpFile);
        foreach ($items as $item) {
            $this->audit($context, "download", $params['uuid'], $item[0]);
        }
        return [
            "filename" => $name . ".zip",
            "filepath" => $tmpFile,
            "headers" => [
                "Content-Type" => "application/zip"
            ],
            "unlink" => true
        ];
    }

    /**
     * Write a ZIP archive of the given paths. Each path is stored below
     * its base name. Already compressed media is stored, not deflated.
     * @param callable|null $progress Called with each archived entry.
     */
    private function writeZip($zipFile, array $paths, $progress = null)
    {
        $zip = new \ZipArchive();
        if (true !== $zip->open($zipFile, \ZipArchive::CREATE |
            \ZipArchive::OVERWRITE)) {
            throw new \OMV\Exception("Failed to create the ZIP archive.");
        }
        $stored = ["jpg", "jpeg", "png", "gif", "webp", "mp4", "mkv",
            "m4v", "mov", "avi", "mp3", "m4a", "aac", "ogg", "flac", "zip",
            "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "iso"];
        $addFile = function ($abs, $entry) use ($zip, $stored, $progress) {
            if (!$zip->addFile($abs, $entry)) {
                throw new \OMV\Exception("Failed to add '%s' to the " .
                    "archive.", $entry);
            }
            if (in_array($this->extOf($entry), $stored, true)) {
                $zip->setCompressionName($entry, \ZipArchive::CM_STORE);
            }
            if (is_callable($progress)) {
                $progress($entry);
            }
        };
        foreach ($paths as $path) {
            $base = basename($path);
            if (!is_dir($path)) {
                $addFile($path, $base);
                continue;
            }
            $zip->addEmptyDir($base);
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path,
                    \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST);
            foreach ($it as $item) {
                $entry = $base . "/" . substr($item->getPathname(),
                    strlen($path) + 1);
                if ($item->isLink()) {
                    // Do not follow links out of the shared folder.
                    continue;
                }
                if ($item->isDir()) {
                    $zip->addEmptyDir($entry);
                } elseif ($item->isFile()) {
                    $addFile($item->getPathname(), $entry);
                }
            }
        }
        if (!$zip->close()) {
            throw new \OMV\Exception("Failed to write the ZIP archive: %s",
                $zip->getStatusString());
        }
    }

    /**
     * Send a file inline so the browser can display it in a new tab.
     * Only content types that cannot run script in the WebGUI origin are
     * served as is; any textual content (including HTML and SVG) is sent
     * as text/plain. Everything else is sent as attachment, so the
     * browser downloads it.
     */
    public function preview($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.path");
        list($rootReal, $relPath, $file) = $this->resolve(
            $params['uuid'], $params['path'], $context);
        if (!is_file($file)) {
            throw new \OMV\Exception("The file does not exist.");
        }
        $mime = strval(@mime_content_type($file));
        $safe = ["image/png", "image/jpeg", "image/gif", "image/webp",
            "image/bmp", "image/avif", "image/x-icon",
            "image/vnd.microsoft.icon", "application/pdf"];
        $disposition = "inline";
        if (in_array($mime, $safe, true) ||
            (1 === preg_match("#^(video|audio)/[\w.+-]+$#", $mime))) {
            $contentType = $mime;
        } elseif ((0 === strpos($mime, "text/")) ||
            in_array($mime, ["application/json", "application/xml",
                "image/svg+xml", "application/x-empty",
                "inode/x-empty"], true)) {
            $contentType = "text/plain; charset=utf-8";
        } else {
            $contentType = "application/octet-stream";
            $disposition = "attachment";
        }
        list($filePath, $unlink) = $this->prepareDownloadFile($file);
        $this->audit($context, "preview", $params['uuid'], $relPath);
        return [
            "filepath" => $filePath,
            "headers" => [
                "Content-Type" => $contentType,
                "Content-Disposition" => sprintf("%s; filename=\"%s\"",
                    $disposition, addcslashes(basename($file), "\"\\")),
                "Cache-Control" => "private, no-store"
            ],
            "unlink" => $unlink
        ];
    }

    /**
     * Append a chunk of an upload. Called by filemanager-upload.php, which
     * receives the multipart request in the WebGUI process and passes the
     * temporary file PHP created for the chunk.
     */
    public function uploadChunk($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.uploadchunk");
        list($rootReal, $relPath, $dir) = $this->resolve(
            $params['uuid'], $params['path'], $context, true);
        if (!is_dir($dir)) {
            throw new \OMV\Exception("The target folder does not exist.");
        }
        // Only accept chunks that PHP-FPM stored for this request, never
        // an arbitrary file named by the caller.
        $chunkFile = realpath($params['filepath']);
        $webgui = posix_getpwnam(\OMV\Environment::get(
            "OMV_WEBGUI_FILE_OWNERGROUP_NAME", "openmediavault-webgui"));
        if ((false === $chunkFile) || !is_file($chunkFile) ||
            (1 !== preg_match("#^/tmp/php[A-Za-z0-9]+$#", $chunkFile)) ||
            (false === $webgui) ||
            (fileowner($chunkFile) !== $webgui['uid'])) {
            throw new \OMV\Exception("Invalid upload chunk.");
        }
        $name = $this->validateName($params['name']);
        $target = build_path(DIRECTORY_SEPARATOR, $dir, $name);
        $part = build_path(DIRECTORY_SEPARATOR, $dir, "." . $name .
            self::PART_SUFFIX);
        $overwrite = boolvalEx($params['overwrite']);
        $offset = intval($params['offset']);
        if (0 === $offset) {
            if ((file_exists($target) || is_link($target)) && !$overwrite) {
                throw new \OMV\Exception("'%s' already exists.", $name);
            }
            if (is_link($part)) {
                unlink($part);
            }
            $out = fopen($part, "wb");
        } else {
            clearstatcache(true, $part);
            if (is_link($part) || !is_file($part) ||
                (filesize($part) !== $offset)) {
                throw new \OMV\Exception("The upload of '%s' is out of " .
                    "sync. Please try again.", $name);
            }
            $out = fopen($part, "ab");
        }
        if (false === $out) {
            throw new \OMV\Exception("Failed to write '%s'.", $name);
        }
        $in = fopen($chunkFile, "rb");
        $copied = stream_copy_to_stream($in, $out);
        fclose($in);
        fclose($out);
        if (false === $copied) {
            throw new \OMV\Exception("Failed to write '%s'.", $name);
        }
        if (boolvalEx($params['final'])) {
            if (is_dir($target) && !is_link($target)) {
                @unlink($part);
                throw new \OMV\Exception("'%s' is a folder and cannot be " .
                    "overwritten.", $name);
            }
            if ((file_exists($target) || is_link($target)) &&
                !$overwrite) {
                @unlink($part);
                throw new \OMV\Exception("'%s' already exists.", $name);
            }
            if (!rename($part, $target)) {
                throw new \OMV\Exception("Failed to store '%s'.", $name);
            }
            $this->inheritOwnership($target, $context);
            $this->audit($context, "upload", $params['uuid'],
                $this->joinRel($relPath, $name),
                sprintf("(%d bytes)", filesize($target)));
        }
        return ["size" => $offset + $copied];
    }

    /* ------------------------------------------------------------------
     * Background operations
     * ------------------------------------------------------------------ */

    private function bgOutput($bgOutputFilename, $line)
    {
        $this->writeBgProcOutput($bgOutputFilename, $line . PHP_EOL);
    }

    /**
     * Copy or move items to another folder, optionally in another
     * shared folder.
     */
    public function transfer($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.transfer");
        $move = ($params['mode'] === "move");
        $overwrite = boolvalEx($params['overwrite']);
        // Resolve everything up front so errors are reported directly.
        $sources = [];
        foreach ($this->splitTokens($params['paths']) as $token) {
            list($rootReal, $relPath, $path) = $this->resolve(
                $params['uuid'], $token, $context, $move, false);
            if ($path === $rootReal) {
                throw new \OMV\Exception("The shared folder root cannot " .
                    "be copied or moved.");
            }
            $sources[] = [$relPath, $path];
        }
        list($destRoot, $destRel, $dest) = $this->resolveRel(
            $params['destuuid'], $params['destpath'], $context, true);
        if (!is_dir($dest)) {
            throw new \OMV\Exception("The destination folder does not " .
                "exist.");
        }
        return $this->execBgProc(function ($bgStatusFilename,
            $bgOutputFilename) use ($params, $context, $move, $overwrite,
            $sources, $dest, $destRel) {
            $errors = [];
            foreach ($sources as list($relPath, $src)) {
                $target = build_path(DIRECTORY_SEPARATOR, $dest,
                    basename($src));
                if (($dest === $src) || (0 === strpos($dest . "/",
                    $src . "/"))) {
                    $errors[] = sprintf(
                        "Skipped '%s': cannot copy or move a folder into " .
                        "itself.", $relPath);
                    $this->bgOutput($bgOutputFilename, end($errors));
                    continue;
                }
                if ($target === $src) {
                    $errors[] = sprintf(
                        "Skipped '%s': source and destination are " .
                        "identical.", $relPath);
                    $this->bgOutput($bgOutputFilename, end($errors));
                    continue;
                }
                $exists = file_exists($target) || is_link($target);
                if ($exists && !$overwrite) {
                    $errors[] = sprintf(
                        "Skipped '%s': the destination already exists.",
                        $relPath);
                    $this->bgOutput($bgOutputFilename, end($errors));
                    continue;
                }
                if ($move && $exists && is_dir($target) &&
                    !is_link($target)) {
                    $errors[] = sprintf(
                        "Skipped '%s': cannot replace the existing folder " .
                        "'%s' by moving. Copy it instead.", $relPath,
                        basename($target));
                    $this->bgOutput($bgOutputFilename, end($errors));
                    continue;
                }
                $cmdArgs = $move ? ["-v", "-f", "--"] :
                    ["-a", "-v", "-f", "--reflink=auto", "--"];
                $cmdArgs[] = escapeshellarg($src);
                $cmdArgs[] = escapeshellarg(rtrim($dest, "/") . "/");
                $cmd = new \OMV\System\Process($move ? "mv" : "cp",
                    $cmdArgs);
                $cmd->setRedirect2to1();
                if (0 !== $this->exec($cmd->getCommandLine(), $output,
                    $bgOutputFilename)) {
                    $errors[] = sprintf("Failed to %s '%s'.", $move ?
                        "move" : "copy", $relPath);
                    continue;
                }
                $this->audit($context, $move ? "move" : "copy",
                    $params['uuid'], $relPath, sprintf("-> %s:/%s",
                    $this->getShare($params['destuuid'])['name'],
                    $this->joinRel($destRel, basename($src))));
            }
            if (!empty($errors)) {
                throw new \OMV\Exception(implode(PHP_EOL, $errors));
            }
            $this->bgOutput($bgOutputFilename, "Done.");
            return "";
        });
    }

    /**
     * Change the permissions of files and directories (administrators
     * only). In recursive mode, the execute bits are only applied to
     * directories and files that are already executable (`X`), and the
     * setuid/setgid/sticky bits only to directories.
     */
    public function chmod($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.chmod");
        $mode = intval(octdec($params['mode']));
        $recursive = boolvalEx($params['recursive']);
        $paths = [];
        foreach ($this->splitTokens($params['paths']) as $token) {
            $paths[] = $this->resolve($params['uuid'], $token, $context,
                true);
        }
        return $this->execBgProc(function ($bgStatusFilename,
            $bgOutputFilename) use ($params, $context, $mode, $recursive,
            $paths) {
            foreach ($paths as list($rootReal, $relPath, $path)) {
                if (!$recursive || !is_dir($path)) {
                    if (!chmod($path, $mode)) {
                        throw new \OMV\Exception("Failed to change the " .
                            "mode of '%s'.", $relPath);
                    }
                } else {
                    $sym = [];
                    foreach (["u" => 6, "g" => 3, "o" => 0] as $who =>
                        $shift) {
                        $bits = ($mode >> $shift) & 7;
                        $sym[] = $who . "=" . (($bits & 4) ? "r" : "") .
                            (($bits & 2) ? "w" : "") .
                            (($bits & 1) ? "X" : "");
                    }
                    $cmd = new \OMV\System\Process("chmod", ["-R", "-v",
                        "--", escapeshellarg(implode(",", $sym)),
                        escapeshellarg($path)]);
                    $cmd->setRedirect2to1();
                    $this->exec($cmd->getCommandLine(), $output,
                        $bgOutputFilename);
                    $special = ($mode >> 9) & 7;
                    $cmd = new \OMV\System\Process("find", [
                        escapeshellarg($path), "-type", "d", "-exec",
                        "chmod", sprintf("%s", escapeshellarg(
                            ((($special & 4) ? "u+s" : "u-s") . "," .
                            (($special & 2) ? "g+s" : "g-s") . "," .
                            (($special & 1) ? "+t" : "-t")))), "{}", "+"]);
                    $cmd->setRedirect2to1();
                    $this->exec($cmd->getCommandLine(), $output,
                        $bgOutputFilename);
                }
                $this->audit($context, "chmod", $params['uuid'], $relPath,
                    sprintf("%04o%s", $mode, $recursive ? " (recursive)" :
                    ""));
            }
            $this->bgOutput($bgOutputFilename, "Done.");
            return "";
        });
    }

    /**
     * Change the owner and group (administrators only).
     */
    public function chown($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_ADMINISTRATOR
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.chown");
        if (false === posix_getpwnam($params['owner'])) {
            throw new \OMV\Exception("The user '%s' does not exist.",
                $params['owner']);
        }
        if (false === posix_getgrnam($params['group'])) {
            throw new \OMV\Exception("The group '%s' does not exist.",
                $params['group']);
        }
        $recursive = boolvalEx($params['recursive']);
        $paths = [];
        foreach ($this->splitTokens($params['paths']) as $token) {
            $paths[] = $this->resolve($params['uuid'], $token, $context,
                true);
        }
        return $this->execBgProc(function ($bgStatusFilename,
            $bgOutputFilename) use ($params, $context, $recursive, $paths) {
            foreach ($paths as list($rootReal, $relPath, $path)) {
                $cmdArgs = $recursive ? ["-R", "-h", "-P"] : [];
                $cmdArgs = array_merge($cmdArgs, ["-v", "--",
                    escapeshellarg($params['owner'] . ":" .
                    $params['group']), escapeshellarg($path)]);
                $cmd = new \OMV\System\Process("chown", $cmdArgs);
                $cmd->setRedirect2to1();
                if (0 !== $this->exec($cmd->getCommandLine(), $output,
                    $bgOutputFilename)) {
                    throw new \OMV\Exception("Failed to change the owner " .
                        "of '%s'.", $relPath);
                }
                $this->audit($context, "chown", $params['uuid'], $relPath,
                    sprintf("%s:%s%s", $params['owner'], $params['group'],
                    $recursive ? " (recursive)" : ""));
            }
            $this->bgOutput($bgOutputFilename, "Done.");
            return "";
        });
    }

    /**
     * Create a ZIP or tar.gz archive of the selected items in the folder
     * that contains them.
     */
    public function compress($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.compress");
        $sources = [];
        $parent = null;
        foreach ($this->splitTokens($params['paths']) as $token) {
            list($rootReal, $relPath, $path) = $this->resolve(
                $params['uuid'], $token, $context, false, false);
            if ($path === $rootReal) {
                throw new \OMV\Exception("The shared folder root cannot " .
                    "be compressed.");
            }
            if (is_null($parent)) {
                $parent = dirname($path);
                $parentRel = dirname($relPath);
            } elseif (dirname($path) !== $parent) {
                throw new \OMV\Exception("All selected items must be in " .
                    "the same folder.");
            }
            $sources[] = $path;
        }
        // The archive is written to the parent folder, so check write
        // access there.
        $this->resolveRel($params['uuid'], $parentRel, $context, true);
        $ext = ($params['format'] === "zip") ? ".zip" : ".tar.gz";
        $name = $this->validateName(preg_replace("/(\.zip|\.tar\.gz)$/i",
            "", $params['name']) . $ext);
        $target = build_path(DIRECTORY_SEPARATOR, $parent, $name);
        if (file_exists($target) || is_link($target)) {
            throw new \OMV\Exception("'%s' already exists.", $name);
        }
        return $this->execBgProc(function ($bgStatusFilename,
            $bgOutputFilename) use ($params, $context, $sources, $parent,
            $parentRel, $target, $name) {
            $part = $target . self::PART_SUFFIX;
            try {
                if ($params['format'] === "zip") {
                    $this->writeZip($part, $sources, function ($entry) use (
                        $bgOutputFilename) {
                        $this->bgOutput($bgOutputFilename, $entry);
                    });
                    $this->bgOutput($bgOutputFilename,
                        "Compressing ...");
                } else {
                    $cmdArgs = ["-c", "-z", "-v", "-f",
                        escapeshellarg($part), "-C", escapeshellarg($parent),
                        "--"];
                    foreach ($sources as $source) {
                        $cmdArgs[] = escapeshellarg(basename($source));
                    }
                    $cmd = new \OMV\System\Process("tar", $cmdArgs);
                    $cmd->setRedirect2to1();
                    if (0 !== $this->exec($cmd->getCommandLine(), $output,
                        $bgOutputFilename)) {
                        throw new \OMV\Exception("Failed to create the " .
                            "archive.");
                    }
                }
                if (!rename($part, $target)) {
                    throw new \OMV\Exception("Failed to store '%s'.",
                        $name);
                }
            } catch (\Exception $e) {
                @unlink($part);
                throw $e;
            }
            $this->inheritOwnership($target, $context);
            $this->audit($context, "compress", $params['uuid'],
                $this->joinRel($parentRel, $name));
            $this->bgOutput($bgOutputFilename, sprintf("Created '%s'.",
                $name));
            return "";
        });
    }

    /**
     * Extract an archive into a new folder next to it, named after the
     * archive. Archives are never extracted over existing files.
     */
    public function extract($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.path");
        list($rootReal, $relPath, $file) = $this->resolve(
            $params['uuid'], $params['path'], $context, true);
        if (!is_file($file) || !$this->isArchive($file)) {
            throw new \OMV\Exception("'%s' is not a supported archive.",
                basename($file));
        }
        $ext = $this->extOf($file);
        $base = substr(basename($file), 0, -(strlen($ext) + 1));
        $targetDir = $this->uniquePath(build_path(DIRECTORY_SEPARATOR,
            dirname($file), ($base === "") ? "archive" : $base));
        return $this->execBgProc(function ($bgStatusFilename,
            $bgOutputFilename) use ($params, $context, $relPath, $file,
            $ext, $targetDir) {
            if (!mkdir($targetDir, 0755)) {
                throw new \OMV\Exception("Failed to create '%s'.",
                    basename($targetDir));
            }
            $this->inheritOwnership($targetDir, $context);
            if ($ext === "zip") {
                // ZipArchive strips absolute paths and `..` components
                // and does not create symlinks.
                $zip = new \ZipArchive();
                if (true !== $zip->open($file, \ZipArchive::RDONLY)) {
                    throw new \OMV\Exception("Failed to open the ZIP " .
                        "archive.");
                }
                for ($i = 0; $i < $zip->numFiles; $i++) {
                    $this->bgOutput($bgOutputFilename, $zip->getNameIndex(
                        $i));
                }
                if (!$zip->extractTo($targetDir)) {
                    $status = $zip->getStatusString();
                    $zip->close();
                    throw new \OMV\Exception("Failed to extract the ZIP " .
                        "archive: %s", $status);
                }
                $zip->close();
            } else {
                // GNU tar refuses absolute and `..` member names and
                // defers creating symlinks, so members cannot be written
                // outside the target directory.
                $cmd = new \OMV\System\Process("tar", ["-x", "-v", "-f",
                    escapeshellarg($file), "-C", escapeshellarg($targetDir),
                    "--no-same-owner", "--no-same-permissions"]);
                $cmd->setRedirect2to1();
                if (0 !== $this->exec($cmd->getCommandLine(), $output,
                    $bgOutputFilename)) {
                    throw new \OMV\Exception("Failed to extract the " .
                        "archive.");
                }
            }
            $this->inheritOwnership($targetDir, $context, true);
            $this->audit($context, "extract", $params['uuid'], $relPath,
                "-> " . basename($targetDir));
            $this->bgOutput($bgOutputFilename, sprintf(
                "Extracted to '%s'.", basename($targetDir)));
            return "";
        });
    }

    /**
     * Show details about a file or directory, including the total size
     * of directories, which may take a while to compute.
     */
    public function getProperties($params, $context)
    {
        $this->validateMethodContext($context, [
            "role" => OMV_ROLE_EVERYONE
        ]);
        $this->validateMethodParams($params, "rpc.filemanager.path");
        list($rootReal, $relPath, $path) = $this->resolve(
            $params['uuid'], $params['path'], $context, false, false);
        return $this->execBgProc(function ($bgStatusFilename,
            $bgOutputFilename) use ($params, $relPath, $path) {
            $out = function ($label, $value) use ($bgOutputFilename) {
                $this->bgOutput($bgOutputFilename, sprintf("%-14s %s",
                    $label . ":", $value));
            };
            $stat = lstat($path);
            $isLink = is_link($path);
            $out("Name", basename($path));
            $out("Location", $this->getShare($params['uuid'])['name'] .
                ":/" . (($relPath === ".") ? "" : $relPath));
            $out("Absolute path", $path);
            if ($isLink) {
                $out("Link target", strval(@readlink($path)) .
                    (file_exists($path) ? "" : " (broken)"));
            }
            $cmd = new \OMV\System\Process("file", ["-b", "--",
                escapeshellarg($path)]);
            $cmd->setQuiet(true);
            $out("Type", trim($cmd->execute()));
            if (!is_dir($path)) {
                $out("MIME type", strval(@mime_content_type($path)));
            }
            $out("Owner", sprintf("%s (%d)", $this->userName($stat['uid']),
                $stat['uid']));
            $out("Group", sprintf("%s (%d)", $this->groupName(
                $stat['gid']), $stat['gid']));
            $out("Mode", sprintf("%04o", $stat['mode'] & 07777));
            $out("Modified", date("c", $stat['mtime']));
            $out("Accessed", date("c", $stat['atime']));
            $out("Changed", date("c", $stat['ctime']));
            $out("Inode", $stat['ino']);
            $out("Hard links", $stat['nlink']);
            $cmd = new \OMV\System\Process("getfacl", ["--omit-header",
                "--absolute-names", "--skip-base", "--",
                escapeshellarg($path)]);
            $cmd->setQuiet(true);
            $cmd->execute($output);
            $acl = trim(implode(PHP_EOL, $output));
            if ($acl !== "") {
                $this->bgOutput($bgOutputFilename, "ACL:");
                $this->bgOutput($bgOutputFilename, $acl);
            }
            if (is_dir($path) && !$isLink) {
                $this->bgOutput($bgOutputFilename,
                    "Calculating size ...");
                $cmd = new \OMV\System\Process("du", ["-s", "-b", "-x",
                    "--", escapeshellarg($path)]);
                $cmd->setQuiet(true);
                $du = intval(strval($cmd->execute()));
                $cmd = new \OMV\System\Process("find", [
                    escapeshellarg($path), "-xdev", "-type", "f", "|",
                    "wc", "-l"]);
                $cmd->setQuiet(true);
                $files = intval(trim(strval($cmd->execute())));
                $cmd = new \OMV\System\Process("find", [
                    escapeshellarg($path), "-xdev", "-mindepth", "1",
                    "-type", "d", "|", "wc", "-l"]);
                $cmd->setQuiet(true);
                $dirs = intval(trim(strval($cmd->execute())));
                $out("Size", sprintf("%s (%d bytes)", binary_format($du),
                    $du));
                $out("Contents", sprintf("%d file(s), %d folder(s)",
                    $files, $dirs));
            } else {
                $out("Size", sprintf("%s (%d bytes)", binary_format(
                    $stat['size']), $stat['size']));
            }
            $cmd = new \OMV\System\Process("df", ["--output=source,target",
                "--", escapeshellarg($path), "|", "tail", "-n", "1"]);
            $cmd->setQuiet(true);
            $out("File system", trim(strval($cmd->execute())));
            return "";
        });
    }
}
