#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measured87 path set with exact source identities and one inert mtab compatibility."""
from collections import ChainMap
import posixpath

import aux_checkpoint as aux
import full_root as roots
import root_path

# Joined to measured paths and held sources. No CLI/config input, wildcard,
# class or prefix grant. etc/mtab alone accepts two source-supported spellings.
# Exact measured path set; values remain expected source identities until live checks.
LINK_NODES = {
    'builder-disabled-hooks/10-openssh-mark-sshd-for-restart.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/20-systemd-sysusers.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/21-systemd-tmpfiles.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/25-systemd-binfmt.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/25-systemd-catalog.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/25-systemd-hwdb.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/25-systemd-sysctl.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/30-systemd-daemon-reload-system.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/30-systemd-daemon-reload-user.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/30-update-mime-database.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/35-systemd-enqueue-marked.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/35-systemd-udev-reload.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/35-systemd-update.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/36-systemd-modules-load.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/40-fontconfig-config.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/40-update-ca-trust.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/60-depmod.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/60-mkinitcpio-remove.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/70-openssh-restart-sshd.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/90-mkinitcpio-install.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/dbus-reload.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/dconf-update.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/detect-old-perl-modules.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/fontconfig.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gdk-pixbuf-query-loaders.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gdk-pixbuf-remove-loaders-cache.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gio-querymodules.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gio-remove-module-cache.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/glib-compile-schemas.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/glib-remove-compiled-schemas.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gtk-query-immodules-3.0.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gtk-remove-immodules-cache.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gtk-update-icon-cache.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gtk4-querymodules.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/gvfsd.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/man-db-remove-cache.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/shared-mime-info-remove-cache.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/texinfo-install.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/texinfo-remove.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/update-desktop-database.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'builder-disabled-hooks/vimdoc.hook': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/dev/null'},
    'etc/alsa/conf.d/50-pipewire.conf': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/alsa/alsa.conf.d/50-pipewire.conf'},
    'etc/mtab': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/proc/self/mounts'},
    'etc/systemd/system/autovt@.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/getty@.service'},
    'etc/systemd/system/dbus-org.freedesktop.network1.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-networkd.service'},
    'etc/systemd/system/dbus-org.freedesktop.resolve1.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-resolved.service'},
    'etc/systemd/system/dbus-org.freedesktop.timesync1.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-timesyncd.service'},
    'etc/systemd/system/getty.target.wants/getty@tty1.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/getty@.service'},
    'etc/systemd/system/multi-user.target.wants/remote-fs.target': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/remote-fs.target'},
    'etc/systemd/system/multi-user.target.wants/sshd.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/sshd.service'},
    'etc/systemd/system/multi-user.target.wants/systemd-networkd.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-networkd.service'},
    'etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-networkd-wait-online.service'},
    'etc/systemd/system/sockets.target.wants/systemd-networkd-resolve-hook.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-networkd-resolve-hook.socket'},
    'etc/systemd/system/sockets.target.wants/systemd-networkd-varlink-metrics.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-networkd-varlink-metrics.socket'},
    'etc/systemd/system/sockets.target.wants/systemd-networkd-varlink.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-networkd-varlink.socket'},
    'etc/systemd/system/sockets.target.wants/systemd-networkd.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-networkd.socket'},
    'etc/systemd/system/sockets.target.wants/systemd-resolved-monitor.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-resolved-monitor.socket'},
    'etc/systemd/system/sockets.target.wants/systemd-resolved-varlink.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-resolved-varlink.socket'},
    'etc/systemd/system/sockets.target.wants/systemd-userdbd.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-userdbd.socket'},
    'etc/systemd/system/sysinit.target.wants/systemd-network-generator.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-network-generator.service'},
    'etc/systemd/system/sysinit.target.wants/systemd-resolved.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-resolved.service'},
    'etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/system/systemd-timesyncd.service'},
    'etc/systemd/user/sockets.target.wants/p11-kit-server.socket': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/usr/lib/systemd/user/p11-kit-server.socket'},
    'usr/bin/aarch64-linux-gnu-c++': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/c++'},
    'usr/bin/aarch64-linux-gnu-g++': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/g++'},
    'usr/bin/aarch64-linux-gnu-gcc': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/gcc'},
    'usr/bin/aarch64-linux-gnu-gcc-ar': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/gcc-ar'},
    'usr/bin/aarch64-linux-gnu-gcc-nm': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/gcc-nm'},
    'usr/bin/aarch64-linux-gnu-gcc-ranlib': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/gcc-ranlib'},
    'usr/bin/hyprland': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/Hyprland'},
    'usr/bin/lua5.5': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/lua'},
    'usr/bin/luac5.5': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/bin/luac'},
    'usr/lib/bfd-plugins/liblto_plugin.so': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/liblto_plugin.so'},
    'usr/lib/libkeyutils.so': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/lib/libkeyutils.so.1'},
    'usr/lib/liblua++5.5.so': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/lib/liblua++.so.5.5.1'},
    'usr/lib/liblua5.5.so': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/lib/liblua.so.5.5.1'},
    'usr/share/X11/xkb': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/xkeyboard-config-2'},
    'usr/share/licenses/libmpdclient/BSD-2-Clause.txt': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/doc/libmpdclient/BSD-2-Clause.txt'},
    'usr/share/licenses/libmpdclient/BSD-3-Clause.txt': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/doc/libmpdclient/BSD-3-Clause.txt'},
    'usr/share/licenses/qt6-declarative': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/licenses/qt6-base'},
    'usr/share/licenses/qt6-translations': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/licenses/qt6-base'},
    'usr/share/licenses/systemd/MIT-0.txt': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/doc/systemd/LICENSES/MIT-0.txt'},
    'usr/share/licenses/vim-runtime/license.txt': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/vim/vim92/doc/uganda.txt'},
    'usr/share/licenses/xz/COPYING': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/doc/xz/COPYING'},
    'usr/share/licenses/xz/COPYING.0BSD': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/doc/xz/COPYING.0BSD'},
    'usr/share/licenses/xz/COPYING.GPLv2': {'type': 'symlink', 'mode': 511, 'uid': 0, 'gid': 0, 'target': '/usr/share/doc/xz/COPYING.GPLv2'},
    'var/lib/dbus/machine-id': {'mode': 511, 'uid': 0, 'gid': 0, 'type': 'symlink', 'target': '/etc/machine-id'},
}
CHAIN_PATHS = tuple(sorted(LINK_NODES))
RESOLVED_ENDPOINTS = {
    'etc/alsa/conf.d/50-pipewire.conf': 'usr/share/alsa/alsa.conf.d/50-pipewire.conf',
    'etc/systemd/system/autovt@.service': 'usr/lib/systemd/system/getty@.service',
    'etc/systemd/system/dbus-org.freedesktop.network1.service': 'usr/lib/systemd/system/systemd-networkd.service',
    'etc/systemd/system/dbus-org.freedesktop.resolve1.service': 'usr/lib/systemd/system/systemd-resolved.service',
    'etc/systemd/system/dbus-org.freedesktop.timesync1.service': 'usr/lib/systemd/system/systemd-timesyncd.service',
    'etc/systemd/system/getty.target.wants/getty@tty1.service': 'usr/lib/systemd/system/getty@.service',
    'etc/systemd/system/multi-user.target.wants/remote-fs.target': 'usr/lib/systemd/system/remote-fs.target',
    'etc/systemd/system/multi-user.target.wants/sshd.service': 'usr/lib/systemd/system/sshd.service',
    'etc/systemd/system/multi-user.target.wants/systemd-networkd.service': 'usr/lib/systemd/system/systemd-networkd.service',
    'etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service': 'usr/lib/systemd/system/systemd-networkd-wait-online.service',
    'etc/systemd/system/sockets.target.wants/systemd-networkd-resolve-hook.socket': 'usr/lib/systemd/system/systemd-networkd-resolve-hook.socket',
    'etc/systemd/system/sockets.target.wants/systemd-networkd-varlink-metrics.socket': 'usr/lib/systemd/system/systemd-networkd-varlink-metrics.socket',
    'etc/systemd/system/sockets.target.wants/systemd-networkd-varlink.socket': 'usr/lib/systemd/system/systemd-networkd-varlink.socket',
    'etc/systemd/system/sockets.target.wants/systemd-networkd.socket': 'usr/lib/systemd/system/systemd-networkd.socket',
    'etc/systemd/system/sockets.target.wants/systemd-resolved-monitor.socket': 'usr/lib/systemd/system/systemd-resolved-monitor.socket',
    'etc/systemd/system/sockets.target.wants/systemd-resolved-varlink.socket': 'usr/lib/systemd/system/systemd-resolved-varlink.socket',
    'etc/systemd/system/sockets.target.wants/systemd-userdbd.socket': 'usr/lib/systemd/system/systemd-userdbd.socket',
    'etc/systemd/system/sysinit.target.wants/systemd-network-generator.service': 'usr/lib/systemd/system/systemd-network-generator.service',
    'etc/systemd/system/sysinit.target.wants/systemd-resolved.service': 'usr/lib/systemd/system/systemd-resolved.service',
    'etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service': 'usr/lib/systemd/system/systemd-timesyncd.service',
    'etc/systemd/user/sockets.target.wants/p11-kit-server.socket': 'usr/lib/systemd/user/p11-kit-server.socket',
    'usr/bin/aarch64-linux-gnu-c++': 'usr/bin/c++',
    'usr/bin/aarch64-linux-gnu-g++': 'usr/bin/g++',
    'usr/bin/aarch64-linux-gnu-gcc': 'usr/bin/gcc',
    'usr/bin/aarch64-linux-gnu-gcc-ar': 'usr/bin/gcc-ar',
    'usr/bin/aarch64-linux-gnu-gcc-nm': 'usr/bin/gcc-nm',
    'usr/bin/aarch64-linux-gnu-gcc-ranlib': 'usr/bin/gcc-ranlib',
    'usr/bin/hyprland': 'usr/bin/Hyprland',
    'usr/bin/lua5.5': 'usr/bin/lua',
    'usr/bin/luac5.5': 'usr/bin/luac',
    'usr/lib/bfd-plugins/liblto_plugin.so': 'usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/liblto_plugin.so',
    'usr/lib/libkeyutils.so': 'usr/lib/libkeyutils.so.1.10',
    'usr/lib/liblua++5.5.so': 'usr/lib/liblua++.so.5.5.1',
    'usr/lib/liblua5.5.so': 'usr/lib/liblua.so.5.5.1',
    'usr/share/X11/xkb': 'usr/share/xkeyboard-config-2',
    'usr/share/licenses/libmpdclient/BSD-2-Clause.txt': 'usr/share/doc/libmpdclient/BSD-2-Clause.txt',
    'usr/share/licenses/libmpdclient/BSD-3-Clause.txt': 'usr/share/doc/libmpdclient/BSD-3-Clause.txt',
    'usr/share/licenses/qt6-declarative': 'usr/share/licenses/qt6-base',
    'usr/share/licenses/qt6-translations': 'usr/share/licenses/qt6-base',
    'usr/share/licenses/systemd/MIT-0.txt': 'usr/share/doc/systemd/LICENSES/MIT-0.txt',
    'usr/share/licenses/vim-runtime/license.txt': 'usr/share/vim/vim92/doc/uganda.txt',
    'usr/share/licenses/xz/COPYING': 'usr/share/doc/xz/COPYING',
    'usr/share/licenses/xz/COPYING.0BSD': 'usr/share/doc/xz/COPYING.0BSD',
    'usr/share/licenses/xz/COPYING.GPLv2': 'usr/share/doc/xz/COPYING.GPLv2',
    'var/lib/dbus/machine-id': 'etc/machine-id',
}
DATA_ONLY_ENDPOINTS = {
    'builder-disabled-hooks/10-openssh-mark-sshd-for-restart.hook': 'dev/null',
    'builder-disabled-hooks/20-systemd-sysusers.hook': 'dev/null',
    'builder-disabled-hooks/21-systemd-tmpfiles.hook': 'dev/null',
    'builder-disabled-hooks/25-systemd-binfmt.hook': 'dev/null',
    'builder-disabled-hooks/25-systemd-catalog.hook': 'dev/null',
    'builder-disabled-hooks/25-systemd-hwdb.hook': 'dev/null',
    'builder-disabled-hooks/25-systemd-sysctl.hook': 'dev/null',
    'builder-disabled-hooks/30-systemd-daemon-reload-system.hook': 'dev/null',
    'builder-disabled-hooks/30-systemd-daemon-reload-user.hook': 'dev/null',
    'builder-disabled-hooks/30-update-mime-database.hook': 'dev/null',
    'builder-disabled-hooks/35-systemd-enqueue-marked.hook': 'dev/null',
    'builder-disabled-hooks/35-systemd-udev-reload.hook': 'dev/null',
    'builder-disabled-hooks/35-systemd-update.hook': 'dev/null',
    'builder-disabled-hooks/36-systemd-modules-load.hook': 'dev/null',
    'builder-disabled-hooks/40-fontconfig-config.hook': 'dev/null',
    'builder-disabled-hooks/40-update-ca-trust.hook': 'dev/null',
    'builder-disabled-hooks/60-depmod.hook': 'dev/null',
    'builder-disabled-hooks/60-mkinitcpio-remove.hook': 'dev/null',
    'builder-disabled-hooks/70-openssh-restart-sshd.hook': 'dev/null',
    'builder-disabled-hooks/90-mkinitcpio-install.hook': 'dev/null',
    'builder-disabled-hooks/dbus-reload.hook': 'dev/null',
    'builder-disabled-hooks/dconf-update.hook': 'dev/null',
    'builder-disabled-hooks/detect-old-perl-modules.hook': 'dev/null',
    'builder-disabled-hooks/fontconfig.hook': 'dev/null',
    'builder-disabled-hooks/gdk-pixbuf-query-loaders.hook': 'dev/null',
    'builder-disabled-hooks/gdk-pixbuf-remove-loaders-cache.hook': 'dev/null',
    'builder-disabled-hooks/gio-querymodules.hook': 'dev/null',
    'builder-disabled-hooks/gio-remove-module-cache.hook': 'dev/null',
    'builder-disabled-hooks/glib-compile-schemas.hook': 'dev/null',
    'builder-disabled-hooks/glib-remove-compiled-schemas.hook': 'dev/null',
    'builder-disabled-hooks/gtk-query-immodules-3.0.hook': 'dev/null',
    'builder-disabled-hooks/gtk-remove-immodules-cache.hook': 'dev/null',
    'builder-disabled-hooks/gtk-update-icon-cache.hook': 'dev/null',
    'builder-disabled-hooks/gtk4-querymodules.hook': 'dev/null',
    'builder-disabled-hooks/gvfsd.hook': 'dev/null',
    'builder-disabled-hooks/man-db-remove-cache.hook': 'dev/null',
    'builder-disabled-hooks/shared-mime-info-remove-cache.hook': 'dev/null',
    'builder-disabled-hooks/texinfo-install.hook': 'dev/null',
    'builder-disabled-hooks/texinfo-remove.hook': 'dev/null',
    'builder-disabled-hooks/update-desktop-database.hook': 'dev/null',
    'builder-disabled-hooks/vimdoc.hook': 'dev/null',
    'etc/mtab': 'proc/self/mounts',
}
MTAB_PATH = 'etc/mtab'
MTAB_TARGETS = ('/proc/mounts', '/proc/self/mounts')



def _literal_matches(name,node):
    expected=LINK_NODES[name]
    if name==MTAB_PATH:
        return (type(node) is dict and node.get('target') in MTAB_TARGETS
                and {k:v for k,v in node.items() if k!='target'}=={k:v for k,v in expected.items() if k!='target'})
    return node==expected


def variant_report(nodes=None):
    node=nodes.get(MTAB_PATH) if nodes is not None else None
    return {'path':MTAB_PATH,'observed_target':node['target'] if node is not None else 'NOT OBSERVED',
        'supported_targets':MTAB_TARGETS,'target_followed':False,'prior_actual_literal_exported':False,
        'source_gap':'absolute conversion producer not attested; proc spelling compatibility only',
        'preservation':'raw literal required equal across source/copy and baseline/precommit/postupdate'}


def _overrides(nodes):
    return {name:dict(nodes[name],target=posixpath.relpath(nodes[name]['target'].lstrip('/'),posixpath.dirname(name) or '.'))
            for name in LINK_NODES if nodes[name]['target'].startswith('/')}


def _data_endpoint(nodes,name):
    aux.need(_literal_matches(name,nodes.get(name)) and nodes[name]['type']=='symlink','selected-data-link-drift')
    endpoint=roots.installer.resolve_nodes(ChainMap(_overrides(nodes),nodes),name)
    aux.need(endpoint==(nodes[name]['target'].lstrip('/') if name==MTAB_PATH else DATA_ONLY_ENDPOINTS[name]) and endpoint not in nodes,'selected-data-endpoint-drift')
    roots.installer.relative(endpoint)
    parts=endpoint.split('/')
    for index in range(1,len(parts)):
        parent=nodes.get('/'.join(parts[:index]))
        aux.need(parent is None or parent['type']=='directory','selected-data-parent-shape')
    return endpoint


def check(observation,limits):
    """Validate the full bounded map, never the truncated public examples."""
    limits.tick(); nodes=observation['nodes']
    aux.need(observation.get('complete') is True and len(nodes)<=limits.max_nodes,'complete-link-observation')
    aux.need(type(CHAIN_PATHS) is tuple and CHAIN_PATHS==tuple(sorted(set(CHAIN_PATHS)))
             and len(LINK_NODES)<=4096 and set(CHAIN_PATHS)<=LINK_NODES.keys()
             and not (RESOLVED_ENDPOINTS.keys() & DATA_ONLY_ENDPOINTS.keys())
             and RESOLVED_ENDPOINTS.keys() | DATA_ONLY_ENDPOINTS.keys()==LINK_NODES.keys(),'finite-source-link-selection')
    for name,expected in LINK_NODES.items():
        limits.tick(); roots.installer.relative(name)
        aux.need(type(expected) is dict and expected.get('type')=='symlink' and _literal_matches(name,nodes.get(name)),'selected-literal-link-drift')
    actual=[]
    for name,node in nodes.items():
        limits.tick()
        if node.get('type')!='symlink': continue
        if node['target'].startswith('/'):
            aux.need(name in LINK_NODES,'unselected-absolute-link'); actual.append(name)
        else:
            try: roots.installer.resolve_nodes(nodes,name)
            except ValueError as error:
                aux.need(str(error)=='absolute payload link','unsupported-link-chain'); actual.append(name)
    aux.need(tuple(sorted(actual))==CHAIN_PATHS,'complete-absolute-chain-set-differs')
    expected_counts={'auxiliary-present':3}
    if actual: expected_counts['absolute-symlink']=len(actual)
    aux.need(observation['unsupported_counts']==expected_counts,'unselected-root-shape')
    for name,endpoint in RESOLVED_ENDPOINTS.items():
        limits.tick(); resolved,_trace=root_path.resolve(nodes,name,limits=limits)
        aux.need(resolved==endpoint and nodes[resolved]['type'] in ('file','directory'),'selected-link-endpoint-drift')
    for name in DATA_ONLY_ENDPOINTS:
        limits.tick(); _data_endpoint(nodes,name)
    return nodes


def view(observation,limits):
    """Private hardlink-validator view; preserve every literal in raw maps."""
    nodes=check(observation,limits)
    projected=dict(nodes); projected.update(_overrides(nodes)); projected.pop(aux.HELPER_NODE,None)
    return dict(observation,nodes=projected,eligible=True,unsupported_counts={})


def protection_endpoint(nodes,name,limits):
    # Data-only endpoints are names for protected-write comparison, never paths
    # granted to Reader, node(), archive extraction or helper execution.
    if name in DATA_ONLY_ENDPOINTS:
        for path,expected in LINK_NODES.items():
            limits.tick(); aux.need(_literal_matches(path,nodes.get(path)),'selected-literal-link-drift')
        return _data_endpoint(nodes,name)
    return root_path.resolve(nodes,name,limits=limits)[0]


def restore_literals(projected,seed):
    for name in LINK_NODES: projected[name]=seed[name]
    projected[aux.HELPER_NODE]=seed[aux.HELPER_NODE]
    return projected
