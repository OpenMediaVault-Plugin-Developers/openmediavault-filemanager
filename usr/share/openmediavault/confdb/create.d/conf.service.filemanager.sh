#!/usr/bin/env dash
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

set -e

. /usr/share/openmediavault/scripts/helper-functions

if ! omv_config_exists "/config/services/filemanager"; then
    omv_config_add_node "/config/services" "filemanager"
    omv_config_add_key "/config/services/filemanager" "enable" "1"
    omv_config_add_key "/config/services/filemanager" "readonly" "0"
    omv_config_add_key "/config/services/filemanager" "showhidden" "1"
    omv_config_add_key "/config/services/filemanager" "maxeditsize" "2"
    omv_config_add_key "/config/services/filemanager" "sharedfolders" ""
    omv_config_add_key "/config/services/filemanager" "usetrash" "1"
    omv_config_add_key "/config/services/filemanager" "auditlog" "1"
    omv_config_add_key "/config/services/filemanager" "allowusers" "0"
fi

exit 0
