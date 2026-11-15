# SPDX-License-Identifier: MIT
"""Finite experimental GLib upgrade/rollback contract; never execute commands."""
OLD='2.88.3-1';NEW='2.90.1-1'
ADDITIONS=frozenset(['adwaita-cursors', 'adwaita-fonts', 'adwaita-icon-theme', 'adwaita-icon-theme-legacy', 'at-spi2-core', 'avahi', 'bubblewrap', 'cachy-asahi-first-login', 'cachy-asahi-first-login-ui', 'cachy-asahi-setup', 'cairo', 'dav1d', 'dconf', 'default-cursors', 'desktop-file-utils', 'duktape', 'fish', 'fontconfig', 'freetype2', 'fribidi', 'fuse-common', 'fuse3', 'gcc-libs', 'gdk-pixbuf2', 'giflib', 'glib-networking', 'glycin', 'gobject-introspection-runtime', 'gperftools', 'gpm', 'graphene', 'graphite', 'gsettings-desktop-schemas', 'gsettings-system-schemas', 'gssdp', 'gst-plugins-bad-libs', 'gst-plugins-base-libs', 'gstreamer', 'gtest', 'gtk-update-icon-cache', 'gtk3', 'gtk4', 'gupnp', 'gupnp-igd', 'harfbuzz', 'hicolor-icon-theme', 'highway', 'iproute2', 'iptables', 'iso-codes', 'jbigkit', 'json-glib', 'lcms2', 'libasan', 'libatomic', 'libbpf', 'libcloudproviders', 'libcolord', 'libcups', 'libdaemon', 'libdatrie', 'libdeflate', 'libdrm', 'libedit', 'libepoxy', 'libfontenc', 'libgfortran', 'libgirepository', 'libglvnd', 'libgudev', 'libice', 'libjpeg-turbo', 'libjxl', 'liblsan', 'libmm-glib', 'libmnl', 'libndp', 'libnetfilter_conntrack', 'libnewt', 'libnfnetlink', 'libnftnl', 'libnice', 'libnl', 'libnm', 'libobjc', 'libpcap', 'libpciaccess', 'libpgm', 'libpipewire', 'libpng', 'libproxy', 'libquadmath', 'librsvg', 'libsm', 'libsodium', 'libsoup3', 'libstemmer', 'libteam', 'libthai', 'libtiff', 'libtsan', 'libubsan', 'libunwind', 'liburing', 'libva', 'libwebp', 'libx11', 'libxau', 'libxcb', 'libxcomposite', 'libxcursor', 'libxdamage', 'libxdmcp', 'libxext', 'libxfixes', 'libxfont2', 'libxft', 'libxi', 'libxinerama', 'libxkbcommon', 'libxkbcommon-x11', 'libxkbfile', 'libxmu', 'libxrandr', 'libxrender', 'libxshmfence', 'libxt', 'libxtst', 'libxv', 'libxxf86vm', 'llvm-libs', 'lm_sensors', 'lzo', 'mesa', 'mobile-broadband-provider-info', 'mpdecimal', 'networkmanager', 'nftables', 'nspr', 'nss', 'numactl', 'orc', 'pango', 'pcre', 'pcsclite', 'pipewire', 'pixman', 'polkit', 'python', 'python-gobject', 'shared-mime-info', 'slang', 'spirv-tools', 'tinysparql', 'vmaf', 'vulkan-icd-loader', 'wayland', 'wpa_supplicant', 'xcb-proto', 'xdg-desktop-portal', 'xdg-desktop-portal-gtk', 'xkeyboard-config', 'xorg-fonts-encodings', 'xorg-server-common', 'xorg-server-xvfb', 'xorg-setxkbmap', 'xorg-xauth', 'xorg-xkbcomp', 'xorg-xprop', 'xorgproto', 'zeromq', 'zsh'])
OLD_SHA='a1498d94c3ff5e52ea157a09bb55bceaa7f94e47ded7c74ac5611d0e0b9b5ec8'
NEW_SHA='c0beb07e62117bf5adef1561580b7878742521a4caea1227bff76a2f894b9bd0'
def plan(baseline,rows,rollback):
 assert len(baseline)==111 and baseline.get('glib2')==OLD and len(rows)==173
 by_name={r['name']:r for r in rows};assert len(by_name)==173 and set(by_name)==ADDITIONS|{'glib2'}and set(by_name)&set(baseline)=={'glib2'}
 assert by_name['glib2']['version']==NEW and by_name['glib2']['sha256']==NEW_SHA
 assert rollback['name']=='glib2'and rollback['version']==OLD and rollback['sha256']==OLD_SHA and rollback['filename']=='glib2-'+OLD+'-aarch64.pkg.tar.xz'
 after={**baseline,**{n:r['version']for n,r in by_name.items()}};assert len(after)==283
 assert all(after[n]==v for n,v in baseline.items()if n!='glib2')
 additions=sorted(set(by_name)-set(baseline));assert len(additions)==172 and 'glib2'not in additions
 return after,additions

def rollback_argv(config,rollback):
 assert config=='/var/lib/arm16k-virtio-seat/pacman.conf'
 assert rollback['filename']=='glib2-'+OLD+'-aarch64.pkg.tar.xz'and rollback['sha256']==OLD_SHA and rollback['version']==OLD
 return ['pacman','--config',config,'--noconfirm','-U','/var/lib/arm16k-virtio-seat/materials/'+rollback['filename']]

def removal_argv(config,names):
 assert config=='/var/lib/arm16k-virtio-seat/pacman.conf'and len(names)==172 and set(names)==ADDITIONS and 'glib2'not in names
 return ['pacman','--config',config,'--noconfirm','-R',*sorted(names)]
