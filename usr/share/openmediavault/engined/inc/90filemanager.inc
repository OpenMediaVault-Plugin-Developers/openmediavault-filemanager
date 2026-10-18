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

// Audit log written by the FileManager RPC, e.g.
// 2026-10-12T10:00:00+0200 nas omv-filemanager[123]: [admin] trash: Media:/a.txt
\OMV\System\LogFileSpec::registerSpecification("filemanager", [
    "command" => "export SYSTEMD_COLORS=0; journalctl --quiet --no-pager " .
        "SYSLOG_IDENTIFIER='omv-filemanager' --output=short-iso",
    "filename" => "filemanager",
    "regex" => "/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2})\s+" .
        "\S+\s+omv-filemanager\[\d+\]:\s+\[([^\]]*)\]\s+([^:]+):\s*(.*)$/",
    "columns" => [
        "ts" => [
            "index" => 1,
            "func" => function ($v) {
                return strpdate($v, "Y-m-d*H:i:sT");
            }
        ],
        "user" => 2,
        "action" => 3,
        "message" => 4
    ]
]);
