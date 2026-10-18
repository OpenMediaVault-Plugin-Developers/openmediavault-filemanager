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

/**
 * Upload page of the file manager plugin.
 *
 * The declarative workbench can only read files as text (`fileInput`), so
 * binary uploads are handled here: GET renders a small upload page, POST
 * receives one chunk of a file and hands it to the FileManager.uploadChunk
 * RPC, which appends it inside the shared folder with root privileges.
 * Files are sent in chunks so the size is not limited by the web server's
 * request body limit. The session of the WebGUI is reused.
 */

function fm_param($name, $pattern)
{
    $value = $_REQUEST[$name] ?? "";
    if (!is_string($value) || (1 !== preg_match($pattern, $value))) {
        throw new \OMV\HttpErrorException(400, sprintf(
            "Invalid parameter '%s'.", $name));
    }
    return $value;
}

function fm_json($status, $data)
{
    http_response_code($status);
    header("Content-Type: application/json");
    header("Cache-Control: no-store");
    print json_encode_safe($data);
}

$isPost = ($_SERVER['REQUEST_METHOD'] ?? "GET") === "POST";

try {
    require_once("openmediavault/autoloader.inc");
    require_once("openmediavault/env.inc");
    require_once("openmediavault/functions.inc");

    $session = &\OMV\Session::getInstance();
    $session->start();
    $session->validate();
    $session->updateLastAccess();
    $context = \OMV\Rpc\Rpc::createContext($session->getUsername(),
        $session->getRole());
    // Release the session lock, the RPC is executed by omv-engined.
    $session->commit();

    $uuid = fm_param("uuid", "/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-" .
        "[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i");
    $path = fm_param("path", "/^[A-Za-z0-9_-]+$/");

    if ($isPost) {
        // Cross-site forms cannot set custom headers, which protects
        // this endpoint against CSRF.
        if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? "") !==
            "XMLHttpRequest") {
            throw new \OMV\HttpErrorException(403, "Forbidden.");
        }
        $chunk = $_FILES['chunk'] ?? null;
        if (!is_array($chunk) || ($chunk['error'] !== UPLOAD_ERR_OK) ||
            !is_uploaded_file($chunk['tmp_name'])) {
            throw new \OMV\HttpErrorException(400, sprintf(
                "The chunk was not received (error %d).",
                is_array($chunk) ? $chunk['error'] : -1));
        }
        $response = \OMV\Rpc\Rpc::call("FileManager", "uploadChunk", [
            "uuid" => $uuid,
            "path" => $path,
            "name" => strval($_POST['name'] ?? ""),
            "offset" => intval($_POST['offset'] ?? -1),
            "final" => ($_POST['final'] ?? "") === "1",
            "overwrite" => ($_POST['overwrite'] ?? "") === "1",
            "filepath" => $chunk['tmp_name']
        ], $context, \OMV\Rpc\Rpc::MODE_REMOTE);
        fm_json(200, ["response" => $response]);
        exit(0);
    }

    $location = \OMV\Rpc\Rpc::call("FileManager", "getLocation", [
        "uuid" => $uuid,
        "path" => $path
    ], $context, \OMV\Rpc\Rpc::MODE_REMOTE);
    $error = null;
} catch (\Exception $e) {
    if ($isPost) {
        fm_json(($e instanceof \OMV\BaseException) ?
            $e->getHttpStatusCode() : 500, [
            "error" => ["message" => $e->getMessage()]
        ]);
        exit(0);
    }
    $error = $e->getMessage();
}

$h = function ($s) {
    return htmlspecialchars(strval($s), ENT_QUOTES, "UTF-8");
};
header("Content-Type: text/html; charset=utf-8");
header("Cache-Control: no-store");
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Upload files</title>
<link rel="icon" href="favicon.svg">
<style>
:root {
  --bg: #f4f5f7; --card: #ffffff; --text: #1f2328; --muted: #656d76;
  --border: #d0d7de; --accent: #1976d2; --accent-soft: #e3effb;
  --ok: #1a7f37; --err: #cf222e; --track: #e7eaee;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #15171a; --card: #1f2226; --text: #e6e8eb; --muted: #9aa3ad;
    --border: #3a3f45; --accent: #64b5f6; --accent-soft: #1d3247;
    --ok: #57c26b; --err: #ff7b72; --track: #2c3036;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 760px; margin: 32px auto; padding: 0 16px; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 8px; padding: 24px;
}
h1 { font-size: 20px; font-weight: 600; margin: 0 0 4px; }
.dest { color: var(--muted); margin: 0 0 20px; word-break: break-all; }
.dest code { color: var(--text); font-family: "Roboto Mono", monospace; }
.drop {
  border: 2px dashed var(--border); border-radius: 8px; padding: 32px 16px;
  text-align: center; cursor: pointer; transition: background .15s;
}
.drop:hover, .drop:focus-visible, .drop.over {
  background: var(--accent-soft); border-color: var(--accent); outline: none;
}
.drop strong { color: var(--accent); }
.row {
  display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
  justify-content: space-between; margin-top: 16px;
}
label.opt { display: flex; gap: 8px; align-items: center; cursor: pointer; }
button {
  font: inherit; font-weight: 600; border: 0; border-radius: 6px;
  padding: 8px 18px; cursor: pointer; background: var(--accent); color: #fff;
}
@media (prefers-color-scheme: dark) { button { color: #0d1117; } }
button:disabled { opacity: .5; cursor: default; }
ul { list-style: none; margin: 20px 0 0; padding: 0; }
li { padding: 10px 0; border-top: 1px solid var(--border); }
.name {
  display: flex; justify-content: space-between; gap: 12px;
  word-break: break-all;
}
.state { color: var(--muted); white-space: nowrap; }
.state.ok { color: var(--ok); } .state.err { color: var(--err); }
.msg { color: var(--err); font-size: 13px; }
.bar {
  height: 4px; background: var(--track); border-radius: 2px;
  margin-top: 6px; overflow: hidden;
}
.bar > div { height: 100%; width: 0; background: var(--accent); }
.hint { color: var(--muted); font-size: 13px; margin-top: 16px; }
.error {
  color: var(--err); background: var(--accent-soft); border-radius: 6px;
  padding: 12px;
}
</style>
</head>
<body>
<main>
  <div class="card">
    <h1>Upload files</h1>
<?php if (!is_null($error)): ?>
    <p class="error"><?= $h($error) ?></p>
    <p class="hint">Log in to the openmediavault web interface and open
      the upload from the file manager again.</p>
<?php else: ?>
    <p class="dest">To <code><?= $h($location['sharename']) ?>:<?=
      $h($location['location']) ?></code></p>
    <div class="drop" id="drop" tabindex="0" role="button">
      Drop files here or <strong>browse</strong>
      <input type="file" id="input" multiple hidden>
    </div>
    <div class="row">
      <label class="opt"><input type="checkbox" id="overwrite">
        Overwrite existing files</label>
      <button id="start" disabled>Upload</button>
    </div>
    <ul id="list"></ul>
    <p class="hint">When the upload is done, close this tab and reload the
      file manager.</p>
<?php endif; ?>
  </div>
</main>
<?php if (is_null($error)): ?>
<script>
(function () {
  "use strict";
  var CHUNK = 8 * 1024 * 1024;
  var target = { uuid: <?= json_encode($uuid) ?>, path: <?= json_encode($path) ?> };
  var drop = document.getElementById("drop");
  var input = document.getElementById("input");
  var list = document.getElementById("list");
  var start = document.getElementById("start");
  var overwrite = document.getElementById("overwrite");
  var queue = [];
  var busy = false;

  function fmtSize(n) {
    var u = ["B", "KiB", "MiB", "GiB", "TiB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : n) + " " + u[i];
  }

  function add(files) {
    Array.prototype.forEach.call(files, function (file) {
      var li = document.createElement("li");
      li.innerHTML = '<div class="name"><span></span>' +
        '<span class="state"></span></div>' +
        '<div class="bar"><div></div></div><div class="msg"></div>';
      li.querySelector(".name span").textContent = file.name;
      li.querySelector(".state").textContent = fmtSize(file.size);
      list.appendChild(li);
      queue.push({ file: file, li: li, done: false });
    });
    start.disabled = busy || !queue.some(function (q) { return !q.done; });
  }

  function send(item, offset) {
    return new Promise(function (resolve, reject) {
      var file = item.file;
      var end = Math.min(offset + CHUNK, file.size);
      var form = new FormData();
      form.append("uuid", target.uuid);
      form.append("path", target.path);
      form.append("name", file.name);
      form.append("offset", String(offset));
      form.append("final", end >= file.size ? "1" : "0");
      form.append("overwrite", overwrite.checked ? "1" : "0");
      form.append("chunk", file.slice(offset, end), "chunk");
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "filemanager-upload.php");
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      xhr.upload.onprogress = function (e) {
        if (e.lengthComputable && file.size) {
          progress(item, (offset + e.loaded * (end - offset) / e.total) /
            file.size);
        }
      };
      xhr.onload = function () {
        var body = null;
        try { body = JSON.parse(xhr.responseText); } catch (e) {}
        if (xhr.status === 200) { resolve(end); return; }
        reject(new Error(body && body.error ? body.error.message :
          "HTTP " + xhr.status + " " + xhr.statusText));
      };
      xhr.onerror = function () { reject(new Error("Network error.")); };
      xhr.send(form);
    });
  }

  function progress(item, ratio) {
    item.li.querySelector(".bar > div").style.width =
      Math.min(100, ratio * 100).toFixed(1) + "%";
  }

  function state(item, text, cls) {
    var el = item.li.querySelector(".state");
    el.textContent = text;
    el.className = "state" + (cls ? " " + cls : "");
  }

  async function run() {
    busy = true;
    start.disabled = true;
    for (var i = 0; i < queue.length; i++) {
      var item = queue[i];
      if (item.done) { continue; }
      state(item, "Uploading …");
      item.li.querySelector(".msg").textContent = "";
      try {
        var offset = 0;
        do { offset = await send(item, offset); }
        while (offset < item.file.size);
        progress(item, 1);
        state(item, "Done", "ok");
        item.done = true;
      } catch (e) {
        state(item, "Failed", "err");
        item.li.querySelector(".msg").textContent = e.message;
      }
    }
    busy = false;
    start.disabled = !queue.some(function (q) { return !q.done; });
  }

  drop.addEventListener("click", function () { input.click(); });
  drop.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
  });
  input.addEventListener("change", function () { add(input.files); input.value = ""; });
  ["dragenter", "dragover"].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (e) { add(e.dataTransfer.files); });
  start.addEventListener("click", run);
  window.addEventListener("beforeunload", function (e) {
    if (busy) { e.preventDefault(); e.returnValue = ""; }
  });
})();
</script>
<?php endif; ?>
</body>
</html>
