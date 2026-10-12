#!/usr/bin/env python3
"""Project fixed updater receipt schemas into bounded public metadata.

No directory traversal, source/binary export, raw logs, argv, environment, or
diagnostic prose. Feed this fresh projection to the unchanged generic exporter.
This adapter neither authorizes publication nor attests cleanup of raw outputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

FILE_LIMIT = 4 * 1024**2
TOTAL_INPUT_LIMIT = 32 * 1024**2
TOTAL_OUTPUT_LIMIT = 4 * 1024**2
NODE_LIMIT = 100000
RETENTION_SECONDS = 7200
PORTABLE_RECIPE_FILES = frozenset({'portable-gzip.py', 'test-portable-gzip.py',
                                 'fixtures/native-arm-reviewed.py', 'transport-revision.json'})
INVENTORY_ROWS = frozenset((('abseil-cpp', '20260817.0-2'), ('acl', '2.4.0-1'), ('adwaita-cursors', '51.0-1'), ('adwaita-fonts', '51.0-2'), ('adwaita-icon-theme', '51.0-1'), ('adwaita-icon-theme-legacy', '46.2-3'), ('alacritty', '0.17.0-1'), ('aquamarine', '0.15.1-1'), ('archlinux-keyring', '20260909-1'), ('archlinuxarm-keyring', '20240419-2'), ('at-spi2-core', '2.62.1-1'), ('attr', '2.6.0-1'), ('audit', '4.2.1-1'), ('autoconf', '2.73-1'), ('automake', '1.19-1'), ('avahi', '1:0.9rc5-1'), ('base', '3-3'), ('base-devel', '1-2'), ('bash', '5.3.20-1'), ('bats', '1.14.0-1'), ('benchmark', '1.9.5-2'), ('binutils', '2.46+r70+g155188ea10a7-1'), ('bison', '3.8.2-8'), ('boost-libs', '1.92.0-1'), ('brightnessctl', '0.5.1-3'), ('brotli', '1.2.0-1'), ('bubblewrap', '0.13.0-1'), ('bzip2', '1.0.8-6'), ('ca-certificates', '20240618-1'), ('ca-certificates-mozilla', '3.131-1'), ('ca-certificates-utils', '20240618-1'), ('cairo', '1.18.6-1'), ('compiler-rt', '23.1.1-1'), ('coreutils', '9.12-2'), ('cpio', '2.15-3'), ('cryptsetup', '2.8.8-1'), ('curl', '8.22.0-1'), ('dav1d', '1.5.4-1'), ('db5.3', '5.3.28-7'), ('dbus', '1.16.2-1'), ('dbus-broker', '37-3'), ('dbus-broker-units', '37-3'), ('dbus-units', '37-3'), ('dconf', '51.0-1'), ('debugedit', '5.3-2'), ('default-cursors', '3-1'), ('desktop-file-utils', '0.28-1'), ('device-mapper', '2.03.43-2'), ('dhcpcd', '10.5.2-1'), ('diffutils', '3.12-2'), ('duktape', '2.7.0-7'), ('e2fsprogs', '1.47.4-1'), ('elfutils', '0.196-1'), ('ex-vi-compat', '3-1'), ('expat', '2.9.0-1'), ('fakeroot', '1:1.37.2-3'), ('file', '5.48-1'), ('filesystem', '2025.10.12-1'), ('findutils', '4.11.0-1'), ('fish', '4.9.3-1'), ('flex', '2.6.4-6'), ('fontconfig', '2:2.18.3-2'), ('freetype2', '2.14.3-1'), ('fribidi', '1.0.17-1'), ('gawk', '5.4.1-1'), ('gc', '8.2.12-1'), ('gcc', '16.1.1+r12+g301eb08fa2c5-1'), ('gcc-libs', '16.1.1+r12+g301eb08fa2c5-1'), ('gdb', '18.1-1'), ('gdb-common', '18.1-1'), ('gdbm', '1.26-2'), ('gdk-pixbuf2', '2.44.8-1'), ('gettext', '1.0-2'), ('giflib', '6.1.3-2'), ('git', '2.56.0-1'), ('glib-networking', '1:2.90.0-1'), ('glib2', '2.90.1-1'), ('glibc', '2.43+r22+g8362e8ce10b2-2'), ('glslang', '1:1.4.363.0-1'), ('glycin', '2.2.2-1'), ('gmp', '6.3.0-3'), ('gnulib-l10n', '20241231-1'), ('gnupg', '2.4.9-3'), ('gnutls', '3.8.13-3'), ('gperftools', '2.18.1-1'), ('gpgme', '2.2.0-1'), ('gpm', '1.20.7.r38.ge82d1a6-7'), ('graphite', '1:1.3.15-1'), ('grep', '3.12-2'), ('groff', '1.24.2-1'), ('gsettings-desktop-schemas', '51.0-1'), ('gsettings-system-schemas', '51.0-1'), ('gtest', '1.18.0-1'), ('gtk-update-icon-cache', '1:4.24.1-1'), ('gtk3', '1:3.24.52-2'), ('guile', '3.0.11-1'), ('gzip', '1.15-1'), ('harfbuzz', '14.6.0-1'), ('hicolor-icon-theme', '0.18-1'), ('highway', '1.4.0-1'), ('hwdata', '0.412-1'), ('hyprcursor', '0.1.13-7'), ('hyprgraphics', '0.5.1-4'), ('hyprland', '0.56.2-4'), ('hyprland-guiutils', '0.2.2-4'), ('hyprlang', '0.6.8-5'), ('hyprtoolkit', '0.6.0-1'), ('hyprutils', '0.14.2-1'), ('hyprwire', '0.3.1-3'), ('iana-etc', '20260617-1'), ('icu', '78.3-1'), ('iniparser', '4.3.2-1'), ('iproute2', '7.2.0-1'), ('iptables', '1:1.8.13-1'), ('iputils', '20250605-1'), ('iso-codes', '4.20.1-1'), ('jansson', '2.15.1-1'), ('jbigkit', '2.1-8'), ('json-c', '0.19-1'), ('json-glib', '1.10.8-1'), ('kbd', '2.10.0-1'), ('keyutils', '1.6.3-4'), ('kmod', '34.2-1'), ('krb5', '1.22.2-1'), ('lcms2', '2.19.1-1'), ('leancrypto', '1.9.1-1'), ('libarchive', '3.8.9-1'), ('libasan', '16.1.1+r12+g301eb08fa2c5-1'), ('libassuan', '3.0.0-1'), ('libatomic', '16.1.1+r12+g301eb08fa2c5-1'), ('libbpf', '1.7.0-1'), ('libcap', '2.78-1'), ('libcap-ng', '0.9.6-1'), ('libcloudproviders', '0.4.1-1'), ('libcolord', '1.4.8-1'), ('libcups', '2:2.4.20-1'), ('libdaemon', '0.14-6'), ('libdatrie', '0.2.14-1'), ('libdecor', '0.2.5-1'), ('libdeflate', '1.26-1'), ('libdisplay-info', '0.3.0-1'), ('libdrm', '2.4.134-1'), ('libedit', '20260512_3.1-1'), ('libei', '1.6.0-1'), ('libelf', '0.196-1'), ('libepoxy', '1.5.10-3'), ('libevdev', '1.14.0-1'), ('libevent', '2.1.13-2'), ('libffi', '3.8.0-1'), ('libfontenc', '1.1.9-1'), ('libgcc', '16.1.1+r12+g301eb08fa2c5-1'), ('libgcrypt', '1.12.4-1'), ('libgfortran', '16.1.1+r12+g301eb08fa2c5-1'), ('libgit2', '1:1.9.7-1'), ('libglvnd', '1.7.0-3'), ('libgomp', '16.1.1+r12+g301eb08fa2c5-1'), ('libgpg-error', '1.61-1'), ('libgudev', '238-3'), ('libidn2', '2.3.8-1'), ('libinput', '1.32.0-1'), ('libisl', '0.28-1'), ('libjpeg-turbo', '3.2.0-2'), ('libjxl', '0.12.0-1'), ('libksba', '1.8.1-1'), ('libldap', '2.7.1-1'), ('liblsan', '16.1.1+r12+g301eb08fa2c5-1'), ('libmakepkg-dropins', '20-2'), ('libmnl', '1.0.5-2'), ('libmpc', '1.4.1-1'), ('libnetfilter_conntrack', '1.1.1-1'), ('libnfnetlink', '1.0.2-2'), ('libnftnl', '1.3.2-1'), ('libnghttp2', '1.70.0-1'), ('libnghttp3', '1.18.0-1'), ('libngtcp2', '1.25.0-1'), ('libnl', '3.12.0-1'), ('libnsl', '2.0.1-2'), ('libobjc', '16.1.1+r12+g301eb08fa2c5-1'), ('libp11-kit', '0.26.5-1'), ('libpcap', '1.11.0-1'), ('libpciaccess', '0.19-1'), ('libpipewire', '1:1.6.9-1'), ('libpng', '1.6.59-1'), ('libproxy', '0.5.12-1'), ('libpsl', '0.21.5-2'), ('libquadmath', '16.1.1+r12+g301eb08fa2c5-1'), ('librsvg', '2:2.63.2-1'), ('libsasl', '2.1.28-5'), ('libseccomp', '2.6.0-1'), ('libsecret', '0.21.8.2-1'), ('libsoup3', '3.8.0-1'), ('libssh2', '1.11.1-7'), ('libstdc++', '16.1.1+r12+g301eb08fa2c5-1'), ('libstemmer', '3.1.1-1'), ('libsysprof-capture', '51.0-1'), ('libtasn1', '4.21.0-1'), ('libthai', '0.1.30-1'), ('libtiff', '4.7.2-1'), ('libtirpc', '1.3.8-1'), ('libtool', '2.6.0+r23+gb08cb0a0-1'), ('libtsan', '16.1.1+r12+g301eb08fa2c5-1'), ('libubsan', '16.1.1+r12+g301eb08fa2c5-1'), ('libunistring', '1.4.2-1'), ('libunwind', '1.8.3-1'), ('libusb', '1.0.30-1'), ('libverto', '0.3.2-6'), ('libwacom', '2.20.0-1'), ('libwebp', '1.6.0-2'), ('libwireplumber', '0.5.18-1'), ('libx11', '1.8.13-2'), ('libxau', '1.0.12-1'), ('libxcb', '1.17.0-1'), ('libxcomposite', '0.4.7-1'), ('libxcrypt', '4.5.2-1'), ('libxcursor', '1.2.3-1'), ('libxcvt', '0.1.3-1'), ('libxdamage', '1.1.7-1'), ('libxdmcp', '1.1.5-2'), ('libxext', '1.3.7-1'), ('libxfixes', '6.0.2-1'), ('libxfont2', '2.0.9-1'), ('libxft', '2.3.9-1'), ('libxi', '1.8.3-1'), ('libxinerama', '1.1.6-1'), ('libxkbcommon', '1.13.2-1'), ('libxkbcommon-x11', '1.13.2-1'), ('libxkbfile', '1.2.0-1'), ('libxml2', '2.15.4-1'), ('libxrandr', '1.5.5-1'), ('libxrender', '0.9.12-1'), ('libxshmfence', '1.3.3-1'), ('libxtst', '1.2.5-1'), ('libxxf86vm', '1.1.7-1'), ('libzip', '1.11.4-1'), ('licenses', '20240728-1'), ('linux-aarch64', '7.2.10-1'), ('linux-api-headers', '7.2-1'), ('linux-firmware', '20260916-1'), ('linux-firmware-amd', '20260916-1'), ('linux-firmware-amdgpu', '20260916-1'), ('linux-firmware-atheros', '20260916-1'), ('linux-firmware-broadcom', '20260916-1'), ('linux-firmware-cirrus', '20260916-1'), ('linux-firmware-intel', '20260916-1'), ('linux-firmware-mediatek', '20260916-1'), ('linux-firmware-nvidia', '20260916-1'), ('linux-firmware-other', '20260916-1'), ('linux-firmware-radeon', '20260916-1'), ('linux-firmware-realtek', '20260916-1'), ('linux-firmware-ti', '20260916-1'), ('linux-firmware-whence', '20260916-1'), ('lld', '23.1.1-1'), ('llhttp', '9.3.1-1'), ('llvm-libs', '23.1.1-1'), ('lm_sensors', '1:3.6.2-1'), ('lmdb', '0.9.35-1'), ('lua', '5.5.1-1'), ('lua54', '5.4.9-1'), ('lz4', '1:1.10.0-2'), ('lzo', '2.10-5'), ('m4', '1.4.21-2'), ('make', '4.4.1-3'), ('mesa', '1:26.2.4-1'), ('mkinitcpio', '42.2-1'), ('mkinitcpio-busybox', '1.36.1-1'), ('mpdecimal', '4.0.1-3'), ('mpfr', '4.2.2-1'), ('mtdev', '1.1.7-1'), ('muparser', '2.3.5-2'), ('nano', '9.2-1'), ('ncurses', '6.6-2'), ('net-tools', '2.10-3'), ('netctl', '1.29-2'), ('nettle', '4.0-1'), ('nftables', '1:1.1.7-3'), ('npth', '1.8-1'), ('openssh', '10.6p1-1'), ('openssl', '3.6.5-1'), ('p11-kit', '0.26.5-1'), ('pacman', '7.1.0.r9.g54d9411-2'), ('pacman-mirrorlist', '20260411-2'), ('pam', '1.7.3-1'), ('pambase', '20260616-1'), ('pango', '1:1.58.2-1'), ('parallel', '20260922-1'), ('patch', '2.8-1'), ('pciutils', '3.15.0-1'), ('pcre2', '10.49-1'), ('perl', '5.42.3-1'), ('perl-error', '0.17030-3'), ('perl-mailtools', '2.22-3'), ('perl-timedate', '2.35-1'), ('pinentry', '1.3.3-1'), ('pipewire', '1:1.6.9-1'), ('pixman', '0.46.4-1.1'), ('pkgconf', '3.0.7-1'), ('popt', '1.19-2'), ('procps-ng', '4.0.7-1'), ('psmisc', '23.7-2'), ('pugixml', '1.16-1'), ('python', '3.14.8-1'), ('re2', '2:2025.11.05-6'), ('readline', '8.3.6-1'), ('rust', '1:1.99.0-1'), ('scdoc', '1.11.5-1'), ('seatd', '0.9.3-1'), ('sed', '4.10-2'), ('shadow', '4.20.0.arch1-1'), ('shared-mime-info', '2.5.1-2'), ('source-highlight', '3.1.9-19'), ('spirv-tools', '1:1.4.363.0-1'), ('sqlite', '3.53.4-1'), ('sudo', '1.9.17.p2-6'), ('swaylock', '1.8.6-1'), ('systemd', '262-1'), ('systemd-libs', '262-1'), ('systemd-resolvconf', '262-1'), ('systemd-sysvcompat', '262-1'), ('tar', '1.35-5'), ('texinfo', '7.3-1'), ('tinysparql', '3.12.0-1'), ('tomlplusplus', '3.4.0-1'), ('tpm2-tss', '4.2.0-2'), ('tzdata', '2026e-1'), ('util-linux', '2.42.4-1'), ('util-linux-libs', '2.42.4-1'), ('vim', '9.2.1164-2'), ('vim-runtime', '9.2.1164-2'), ('wayland', '1.26.0-1'), ('wayland-protocols', '1.49-1'), ('which', '2.25-1'), ('wireplumber', '0.5.18-1'), ('wofi', '1.5.3-1'), ('xcb-proto', '1.17.0-4'), ('xcb-util', '0.4.1-2'), ('xcb-util-errors', '1.0.1-2'), ('xcb-util-image', '0.4.1-3'), ('xcb-util-keysyms', '0.4.1-5'), ('xcb-util-renderutil', '0.3.10-2'), ('xcb-util-wm', '0.4.2-2'), ('xkeyboard-config', '2.48-1'), ('xorg-fonts-encodings', '1.1.0-2'), ('xorg-server-common', '21.1.25-1'), ('xorg-setxkbmap', '1.3.5-1'), ('xorg-xkbcomp', '1.5.0-1'), ('xorg-xprop', '1.2.8-1'), ('xorg-xwayland', '24.1.14-1'), ('xorgproto', '2026.1-1'), ('xxhash', '0.8.4-1'), ('xz', '5.8.4-1'), ('zlib', '1:1.3.2-3'), ('zlib-ng', '2.3.3-1'), ('zsh', '5.9.2-1'), ('zstd', '1.5.7-3')))
TARGET = 'aarch64-unknown-linux-gnu'
# Generated data allowlists from all 167 checksum-audited registry manifests.
# Source: F02 vendor bundle, original Cargo.lock SHA256 0f12cdc2...faa3753.
PACKAGE_IDENTITIES = frozenset('aho-corasick@1.1.5 anstream@1.0.0 anstyle-parse@1.0.0 anstyle-query@1.1.5 anstyle-wincon@3.0.11 anstyle@1.0.14 anyhow@1.0.104 arch-update-tray@4.4.2 async-broadcast@0.7.2 async-recursion@1.1.1 async-trait@0.1.92 autocfg@1.5.1 bitflags@1.3.2 bitflags@2.13.2 block@0.1.6 bumpalo@3.20.3 bytes@1.12.1 cc@1.4.6 cfg-expr@0.20.9 cfg-if@1.0.4 colorchoice@1.0.5 defmt-macros@1.1.1 defmt-parser@1.0.0 defmt@1.1.1 endi@1.1.1 enumflags2@0.7.12 enumflags2_derive@0.7.12 env_filter@2.0.0 env_logger@0.11.11 equivalent@1.0.2 errno@0.3.14 event-listener-strategy@0.5.4 event-listener@5.4.2 fastrand@2.5.0 find-msvc-tools@0.1.12 fsevent-sys@4.1.0 futures-channel@0.3.34 futures-core@0.3.34 futures-executor@0.3.34 futures-io@0.3.34 futures-lite@2.6.1 futures-macro@0.3.34 futures-task@0.3.34 futures-util@0.3.34 getrandom@0.4.3 gettext-rs@0.8.0 gettext-sys@0.27.0 gio-sys@0.22.9 gio-unix-sys@0.22.9 gio-unix@0.22.8 gio@0.22.9 glib-macros@0.22.9 glib-sys@0.22.9 glib@0.22.9 gobject-sys@0.22.9 hashbrown@0.17.1 heck@0.5.0 hex@0.4.3 indexmap@2.14.2 inotify-sys@0.1.8 inotify@0.11.5 is_terminal_polyfill@1.70.2 itoa@1.0.18 jiff-core@0.1.1 jiff-static@0.2.37 jiff@0.2.37 js-sys@0.3.105 kqueue-sys@1.1.2 kqueue@1.2.1 ksni@0.3.6 lazy_static@1.5.0 libc@0.2.189 linux-raw-sys@0.12.1 locale_config@0.3.0 log@0.4.34 malloc_buf@0.0.6 memchr@2.8.3 memoffset@0.9.1 mio@1.2.3 notify-types@2.1.0 notify@8.2.0 objc-foundation@0.1.1 objc@0.2.7 objc_id@0.1.1 once_cell@1.21.4 once_cell_polyfill@1.70.2 ordered-stream@0.2.0 parking@2.2.1 pastey@0.2.3 pin-project-lite@0.2.17 pkg-config@0.3.34 portable-atomic-util@0.2.8 portable-atomic@1.15.0 proc-macro-crate@3.5.0 proc-macro2@1.0.107 quote@1.0.47 r-efi@6.0.0 regex-automata@0.4.18 regex-syntax@0.8.11 regex@1.13.1 rustix@1.1.4 rustversion@1.0.23 same-file@1.0.6 serde@1.0.229 serde_core@1.0.229 serde_derive@1.0.229 serde_json@1.0.151 serde_repr@0.1.21 serde_spanned@1.1.1 shlex@2.0.1 signal-hook-registry@1.4.8 slab@0.4.12 smallvec@1.16.1 socket2@0.6.5 syn@2.0.119 syn@3.0.5 system-deps@9.0.0 target-lexicon@0.13.5 temp-dir@0.1.16 tempfile@3.27.0 thiserror-impl@2.0.20 thiserror@2.0.20 tokio-macros@2.7.2 tokio@1.53.1 toml@1.1.6+spec-1.1.0 toml_datetime@1.1.1+spec-1.1.0 toml_edit@0.25.15+spec-1.1.0 toml_parser@1.1.3+spec-1.1.0 toml_writer@1.1.2+spec-1.1.0 tracing-attributes@0.1.31 tracing-core@0.1.36 tracing@0.1.44 uds_windows@1.2.1 unicode-ident@1.0.24 utf8parse@0.2.2 uuid@1.26.1 version-compare@0.2.1 walkdir@2.5.0 wasi@0.11.1+wasi-snapshot-preview1 wasm-bindgen-macro-support@0.2.128 wasm-bindgen-macro@0.2.128 wasm-bindgen-shared@0.2.128 wasm-bindgen@0.2.128 winapi-i686-pc-windows-gnu@0.4.0 winapi-util@0.1.11 winapi-x86_64-pc-windows-gnu@0.4.0 winapi@0.3.9 windows-link@0.2.1 windows-sys@0.60.2 windows-sys@0.61.2 windows-targets@0.53.5 windows_aarch64_gnullvm@0.53.1 windows_aarch64_msvc@0.53.1 windows_i686_gnu@0.53.1 windows_i686_gnullvm@0.53.1 windows_i686_msvc@0.53.1 windows_x86_64_gnu@0.53.1 windows_x86_64_gnullvm@0.53.1 windows_x86_64_msvc@0.53.1 winnow@1.0.4 zbus@5.19.0 zbus_macros@5.19.0 zbus_names@4.3.4 zcheapstr@1.1.0 zmij@1.0.23 zvariant@5.15.0 zvariant_derive@5.15.0 zvariant_utils@4.2.0'.split())
FEATURE_NAMES = frozenset('Wdk Wdk_Devices Wdk_Devices_Bluetooth Wdk_Devices_HumanInterfaceDevice Wdk_Foundation Wdk_Graphics Wdk_Graphics_Direct3D Wdk_NetworkManagement Wdk_NetworkManagement_Ndis Wdk_NetworkManagement_WindowsFilteringPlatform Wdk_Storage Wdk_Storage_FileSystem Wdk_Storage_FileSystem_Minifilters Wdk_System Wdk_System_IO Wdk_System_Memory Wdk_System_OfflineRegistry Wdk_System_Registry Wdk_System_SystemInformation Wdk_System_SystemServices Wdk_System_Threading Win32 Win32_Data Win32_Data_HtmlHelp Win32_Data_RightsManagement Win32_Devices Win32_Devices_AllJoyn Win32_Devices_Beep Win32_Devices_BiometricFramework Win32_Devices_Bluetooth Win32_Devices_Cdrom Win32_Devices_Communication Win32_Devices_DeviceAndDriverInstallation Win32_Devices_DeviceQuery Win32_Devices_Display Win32_Devices_Dvd Win32_Devices_Enumeration Win32_Devices_Enumeration_Pnp Win32_Devices_Fax Win32_Devices_HumanInterfaceDevice Win32_Devices_Nfc Win32_Devices_Nfp Win32_Devices_PortableDevices Win32_Devices_Properties Win32_Devices_Pwm Win32_Devices_Sensors Win32_Devices_SerialCommunication Win32_Devices_Tapi Win32_Devices_Usb Win32_Devices_WebServicesOnDevices Win32_Foundation Win32_Gaming Win32_Globalization Win32_Graphics Win32_Graphics_Dwm Win32_Graphics_Gdi Win32_Graphics_GdiPlus Win32_Graphics_Hlsl Win32_Graphics_OpenGL Win32_Graphics_Printing Win32_Graphics_Printing_PrintTicket Win32_Management Win32_Management_MobileDeviceManagementRegistration Win32_Media Win32_Media_Audio Win32_Media_DxMediaObjects Win32_Media_KernelStreaming Win32_Media_Multimedia Win32_Media_Streaming Win32_Media_WindowsMediaFormat Win32_NetworkManagement Win32_NetworkManagement_Dhcp Win32_NetworkManagement_Dns Win32_NetworkManagement_InternetConnectionWizard Win32_NetworkManagement_IpHelper Win32_NetworkManagement_Multicast Win32_NetworkManagement_Ndis Win32_NetworkManagement_NetBios Win32_NetworkManagement_NetManagement Win32_NetworkManagement_NetShell Win32_NetworkManagement_NetworkDiagnosticsFramework Win32_NetworkManagement_P2P Win32_NetworkManagement_QoS Win32_NetworkManagement_Rras Win32_NetworkManagement_Snmp Win32_NetworkManagement_WNet Win32_NetworkManagement_WebDav Win32_NetworkManagement_WiFi Win32_NetworkManagement_WindowsConnectionManager Win32_NetworkManagement_WindowsFilteringPlatform Win32_NetworkManagement_WindowsFirewall Win32_NetworkManagement_WindowsNetworkVirtualization Win32_Networking Win32_Networking_ActiveDirectory Win32_Networking_Clustering Win32_Networking_HttpServer Win32_Networking_Ldap Win32_Networking_WebSocket Win32_Networking_WinHttp Win32_Networking_WinInet Win32_Networking_WinSock Win32_Networking_WindowsWebServices Win32_Security Win32_Security_AppLocker Win32_Security_Authentication Win32_Security_Authentication_Identity Win32_Security_Authorization Win32_Security_Credentials Win32_Security_Cryptography Win32_Security_Cryptography_Catalog Win32_Security_Cryptography_Certificates Win32_Security_Cryptography_Sip Win32_Security_Cryptography_UI Win32_Security_DiagnosticDataQuery Win32_Security_DirectoryServices Win32_Security_EnterpriseData Win32_Security_ExtensibleAuthenticationProtocol Win32_Security_Isolation Win32_Security_LicenseProtection Win32_Security_NetworkAccessProtection Win32_Security_WinTrust Win32_Security_WinWlx Win32_Storage Win32_Storage_Cabinets Win32_Storage_CloudFilters Win32_Storage_Compression Win32_Storage_DistributedFileSystem Win32_Storage_FileHistory Win32_Storage_FileSystem Win32_Storage_Imapi Win32_Storage_IndexServer Win32_Storage_InstallableFileSystems Win32_Storage_IscsiDisc Win32_Storage_Jet Win32_Storage_Nvme Win32_Storage_OfflineFiles Win32_Storage_OperationRecorder Win32_Storage_Packaging Win32_Storage_Packaging_Appx Win32_Storage_ProjectedFileSystem Win32_Storage_StructuredStorage Win32_Storage_Vhd Win32_Storage_Xps Win32_System Win32_System_AddressBook Win32_System_Antimalware Win32_System_ApplicationInstallationAndServicing Win32_System_ApplicationVerifier Win32_System_ClrHosting Win32_System_Com Win32_System_Com_Marshal Win32_System_Com_StructuredStorage Win32_System_Com_Urlmon Win32_System_ComponentServices Win32_System_Console Win32_System_CorrelationVector Win32_System_DataExchange Win32_System_DeploymentServices Win32_System_DeveloperLicensing Win32_System_Diagnostics Win32_System_Diagnostics_Ceip Win32_System_Diagnostics_Debug Win32_System_Diagnostics_Debug_Extensions Win32_System_Diagnostics_Etw Win32_System_Diagnostics_ProcessSnapshotting Win32_System_Diagnostics_ToolHelp Win32_System_Diagnostics_TraceLogging Win32_System_DistributedTransactionCoordinator Win32_System_Environment Win32_System_ErrorReporting Win32_System_EventCollector Win32_System_EventLog Win32_System_EventNotificationService Win32_System_GroupPolicy Win32_System_HostCompute Win32_System_HostComputeNetwork Win32_System_HostComputeSystem Win32_System_Hypervisor Win32_System_IO Win32_System_Iis Win32_System_Ioctl Win32_System_JobObjects Win32_System_Js Win32_System_Kernel Win32_System_LibraryLoader Win32_System_Mailslots Win32_System_Mapi Win32_System_Memory Win32_System_Memory_NonVolatile Win32_System_MessageQueuing Win32_System_MixedReality Win32_System_Ole Win32_System_PasswordManagement Win32_System_Performance Win32_System_Performance_HardwareCounterProfiling Win32_System_Pipes Win32_System_Power Win32_System_ProcessStatus Win32_System_Recovery Win32_System_Registry Win32_System_RemoteDesktop Win32_System_RemoteManagement Win32_System_RestartManager Win32_System_Restore Win32_System_Rpc Win32_System_Search Win32_System_Search_Common Win32_System_SecurityCenter Win32_System_Services Win32_System_SetupAndMigration Win32_System_Shutdown Win32_System_StationsAndDesktops Win32_System_SubsystemForLinux Win32_System_SystemInformation Win32_System_SystemServices Win32_System_Threading Win32_System_Time Win32_System_TpmBaseServices Win32_System_UserAccessLogging Win32_System_Variant Win32_System_VirtualDosMachines Win32_System_WindowsProgramming Win32_System_Wmi Win32_UI Win32_UI_Accessibility Win32_UI_ColorSystem Win32_UI_Controls Win32_UI_Controls_Dialogs Win32_UI_HiDpi Win32_UI_Input Win32_UI_Input_Ime Win32_UI_Input_KeyboardAndMouse Win32_UI_Input_Pointer Win32_UI_Input_Touch Win32_UI_Input_XboxController Win32_UI_InteractionContext Win32_UI_Magnification Win32_UI_Shell Win32_UI_Shell_Common Win32_UI_Shell_PropertiesSystem Win32_UI_TabletPC Win32_UI_TextServices Win32_UI_WindowsAndMessaging Win32_Web Win32_Web_InternetExplorer accctrl aclapi activation adhoc aho-corasick align all all-apis alloc allocator-api2 allocator_api anstream anstyle anstyle-query anstyle-wincon appmgmt arbitrary arbitrary_precision arch_z80 arch_zkasm arrayvec ascii async-await async-await-macro async-executor async-fs async-io async-lock async-process async-task atomic atomic-polyfill attributes audioclient audiosessiontypes auto auto-color auxvec avoid-default-panic avrt backtrace basetsd bcrypt bench_allocator_api bilock binary bincode bits bits10_1 bits1_5 bits2_0 bits2_5 bits3_0 bits4_0 bits5_0 bitscfg bitsmsg blocking blocking-api bluetoothapis bluetoothleapis bootparam borsh borsh-derive boxed bthdef bthioctl bthledef bthsdpdef btrfs bugcodes bus-impl bytemuck bytes camino cderr cfg cfg-target-has-atomic cfgmgr32 cguid channel chrono clone-impls collections color combaseapi coml2api commapi commctrl commdlg commoncontrols compat compiler_builtins compiletests consoleapi const-extern-fn const_generics const_new core corecrt corsym critical-section crossbeam-channel d2d1 d2d1_1 d2d1_2 d2d1_3 d2d1effectauthor d2d1effects d2d1effects_1 d2d1effects_2 d2d1svg d2dbasetypes d3d d3d10 d3d10_1 d3d10_1shader d3d10effect d3d10misc d3d10sdklayers d3d10shader d3d11 d3d11_1 d3d11_2 d3d11_3 d3d11_4 d3d11on12 d3d11sdklayers d3d11shader d3d11tokenizedprogramformat d3d12 d3d12sdklayers d3d12shader d3d9 d3d9caps d3d9types d3dcommon d3dcompiler d3dcsx d3dkmdt d3dkmthk d3dukmdt d3dx10core d3dx10math d3dx10mesh datetimeapi davclnt dbghelp dbt dcommon dcomp dcompanimation dcomptypes dde ddraw ddrawi ddrawint debug debugapi default default-hasher defmt derive deserialize_in_place devguid devicetopology devpkey devpropdef dfa dfa-build dfa-onepass dfa-search dinput dinputd disable-fiq dispex display dmksctl dmusicc docobj docs documenttarget dot1x dpa_dsa dpapi drain_filter drain_keep_rest dsgetdc dsound dsrole dvp dwmapi dwrite dwrite_1 dwrite_2 dwrite_3 dxdiag dxfile dxgi dxgi1_2 dxgi1_3 dxgi1_4 dxgi1_5 dxgi1_6 dxgidebug dxgiformat dxgitype dxva2api dxvahd eaptypes elf elf_uapi enable-interning enclaveapi encoding-raw encoding-rzcobs endpointvolume enumflags2 equivalent errhandlingapi errno event everything evntcons evntprov evntrace example_generated exception excpt exdisp extra-platforms extra-traits extra_traits fallback fast-rng fast_hash fastrand fibersapi fileapi float float_roundtrip flume fold foldhash force-amo freebsd-native fs fsevent-sys full functiondiscoverykeys_devpkey futures futures-channel futures-core futures-core-03-stream futures-executor futures-io futures-lite futures-macro futures-sink futures-task futures-util futures_01 general getrandom gettext-system gg-alloc gio gio-sys gl-gl guiddef gvariant gz handleapi heapapi heapless hidclass hidpi hidsdi hidusage highlevelmonitorconfigurationapi hstring http humantime hybrid if_arp if_ether if_packet if_tun ifdef ifmib image imm impl-debug impl-default impl_bincode in6addr inaddr indexmap inline-more inno inspectable interlockedapi internal-instrument internal-instrument-pikevm intsafe io io-compat io-std io-uring io-util io_uring ioapiset ioctl ip_in_core ipexport iphlpapi ipifcons ipmib iprtrmib iptypes is_terminal_polyfill jiff jiff-static jiff-tzdb jiff-tzdb-platform jobapi jobapi2 jobserver js js-sys knownfolders kqueue ks ksmedia ktmtypes ktmw32 kv kv_serde kv_std kv_sval kv_unstable kv_unstable_serde kv_unstable_std kv_unstable_sval l2cmn landlock libc libc_errno libloaderapi limits linux_4_11 linux_5_1 linux_5_11 linux_latest lmaccess lmalert lmapibuf lmat lmcons lmdfs lmerrlog lmjoin lmmsg lmremutl lmrepl lmserver lmshare lmstats lmsvc lmuse lmwksta log log-always log_kv log_macros logging loom loop_device lowlevelmonitorconfigurationapi lsalookup macos_fsevent macos_kqueue macro-diagnostics macros malloc_size_of max_level_debug max_level_error max_level_info max_level_off max_level_trace max_level_warn may_dangle md-5 md5 memchr memoryapi mempolicy meta minschannel minwinbase minwindef mio mm mmdeviceapi mmeapi mmreg mmsystem mount mprapidef msaatext mscat mschapp msrv mssip mstcpip mswsock mswsockdef namedpipeapi namespaceapi native nb30 ncrypt net netioapi netlink nfa nfa-backtrack nfa-pikevm nfa-thompson nightly nldef no-panic no_std ntddndis ntddscsi ntddser ntdef ntlsa ntsecapi ntstatus oaidl objbase objc_exception objidl objidlbase ocidl ole2 oleauto olectl oleidl once_cell opmapi option-as-array os-ext os-poll ostree-tests p2p parallel param parking parking_lot parking_lot_core parse parser parsing pattern pdh perf perf-backtrack perf-cache perf-dfa perf-dfa-full perf-inline perf-literal perf-literal-multisubstring perf-literal-substring perf-onepass perflib physicalmonitorenumerationapi pipe pkg playsoundapi portable-atomic portable-atomic-alloc portable-atomic-util portable_atomic_crate portabledevice portabledeviceapi portabledevicetypes powerbase powersetting powrprof prctl preserve_order printing proc-macro proc-macro-crate proc_macro_crate process processenv processsnapshot processthreadsapi processtopologyapi profileapi propidl propkey propkeydef propsys prsht psapi ptrace pty qos quickcheck quote race rand rand_core raw-entry raw_value rayon rc realtimeapiset reason regex regex-syntax release_max_level_debug release_max_level_error release_max_level_info release_max_level_off release_max_level_trace release_max_level_warn require-cas restartmanager restrictederrorinfo result rmxfguid rng rng-getrandom rng-rand roapi robuffer roerrorapi rpc rpcdce rpcndr rs-log rt rt-multi-thread rtinfo runtime rustc-dep-of-std rustc-internal-api rustc-std-workspace-alloc rustc-std-workspace-core rustversion s-mode sapi sapi51 sapi53 sapiddk sapiddk51 schannel schedule-latency sddl securityappcontainer securitybaseapi serde serde-serialize serde_bytes serde_core serde_derive serde_json serde_spanned serde_support serialization-compat-6 servprov setupapi sha1 sha1_smol shellapi shellscalingapi shlobj shm shobjidl shobjidl_core shtypes signal signal-hook-registry simd sink slab slog socket2 softpub span-locations spans spapidef specialization spellcheck spin spin_no_std sporder sql sqlext sqltypes sqlucode sspi static static-tz std stdio stralign stream strict-macro stringapiset strmif subauth sval sval_ref sync synchapi syntax sys_rng sysinfoapi system system-deps-meta systemtopologyapi target-lexicon targets task-local taskdump taskschd tcpestats tcpmib terminal_size termios test test-util test_debug textstor thread thread-pool threadpoolapiset threadpoollegacyapiset time timeapi timezoneapi tlhelp32 tokio tokio-io tokio-macros tokio-vsock toml_parser toml_writer tracing tracing-attributes transportsettingcommon try_close tvout tz-fat tz-system tzdb tzdb-bundle-always tzdb-bundle-platform tzdb-concatenated tzdb-zoneinfo udpmib unbounded unbounded_depth unicode unicode-age unicode-bool unicode-case unicode-gencat unicode-perl unicode-script unicode-segment unicode-word-boundary union unknwnbase unsafe unsafe-assume-privileged unsafe-assume-single-core unsafe-eval unstable unstable-doc unstable-kv unstable-recover unstable-test unstable_const unstable_offset_of unty url urlhist urlmon usb usbioctl usbiodef usbscan usbspec use-explicitly-provided-auxv use-libc use-libc-auxv use_std userenv usp10 utf8 utf8parse utilapiset uuid uuid-rng-internal-lib uxtheme v1 v2_58 v2_60 v2_62 v2_64 v2_66 v2_68 v2_70 v2_72 v2_74 v2_76 v2_78 v2_80 v2_82 v2_84 v2_86 v2_88 v2_90 v3 v4 v5 v6 v7 v8 vadefs valuable value-bag vcruntime verify_message visit visit-mut vm_sockets vsbackup vsock vss vsserror vswriter wasm-bindgen wasm_js wbemads wbemcli wbemdisp wbemprov wbemtran wct web-time werapi which winbase wincodec wincodecsdk wincon wincontypes wincred wincrypt windef windot11 windows-link windows-sys windowsceip windowsx winefs winerror winevt wingdi winhttp wininet winineti winioctl winnetwk winnls winnow winnt winreg winsafer winscard winsmcrd winsock2 winspool winstring winsvc wintrust winusb winusbio winuser winver wlanapi wlanihv wlanihvtypes wlantypes wlclient wmistr wnnc wow64apiset wpdmtpextensions write write-all-vectored ws2bth ws2def ws2ipdef ws2spi ws2tcpip wtsapi32 wtypes wtypesbase xdp xinput xxx_debug_only_print_generated_code xz zerocopy zip'.split())
RECIPE_FILES = frozenset({'cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a-sanitized.tar.gz', 'materializer-generation.json', 'runner-ready-pins.json', 'fixtures/native-arm-original.py'}) | frozenset('.SRCINFO ICON-LICENSE NOTICE PKGBUILD README.md additional-cargo-licenses.json apple-policy.patch asahi-policy.py audit-cargo.py audit-source.py behavior.patch build-gate.py build-policy.json build-script-review.json builder-extension-discovery.json builder-extension-proposal.json cachy-update-vendor.tar.gz cargo-audit.json historical-notice-followup.json initial-source-validation.json linux-closure-initial-proposal.json linux-closure-proposal.json linux-closure.py materialize-inputs.py native-entry.py patched-source-ledger.json public-evidence.py recipe-validation.json runner-inputs.lock.json source-audit.json test-asahi-policy.py test-audit-cargo.py test-gate.py test-linux-closure.py test-materialize-inputs.py test-native.py test-patches.py test-public-evidence.py test-recipe-gate.py test-source.py test-upstream.py test-verify-updater.py test-worker-build.py test-worker.py updater-native.py updater-sanitized.tar.gz updater-source.tar.gz validation.json verify-updater.py worker-build.py worker-metadata.py'.split())
RECIPE_FILES |= PORTABLE_RECIPE_FILES
ERROR_TYPES = frozenset('ValueError TypeError KeyError RuntimeError OSError FileNotFoundError PermissionError FileExistsError IsADirectoryError NotADirectoryError UnicodeError UnicodeDecodeError JSONDecodeError TimeoutExpired CalledProcessError KeyboardInterrupt BuildCancelled MaterializeError Cancelled SystemExit AcquisitionError AuditError'.split())
STAGES = frozenset('input-validation native-probe input-authentication image-bootstrap worker-1 worker-2 pair-comparison finalized input-snapshot worker-launch worker-inspection package-inspection container-cleanup complete'.split())
STATUSES = frozenset({'RUNNING', 'STARTING', 'PASS', 'FAIL', 'CANCELLED', 'NOT RUN', 'NOT ACCEPTED', 'FAIL-container-cleanup', 'PASS-private-native-package-static-checks'})
TOOLS = frozenset('pacman rustc rustdoc cargo gcc cc ld pkg-config make scdoc git python bash makepkg readelf'.split())


class Invalid(ValueError):
    pass


def need(condition):
    if not condition:
        raise Invalid('invalid allowed field')


def enum(*values):
    def validate(value):
        need(type(value) is str and value in values)
        return value
    return validate


def integer(maximum=2**63-1, minimum=0):
    def validate(value):
        need(type(value) is int and minimum <= value <= maximum)
        return value
    return validate


def boolean(value):
    need(type(value) is bool)
    return value


def text(pattern, maximum):
    def validate(value):
        need(type(value) is str and len(value) <= maximum and re.fullmatch(pattern, value))
        return value
    return validate


HASH = text(r'[0-9a-f]{64}', 64)
IMAGE = text(r'sha256:[0-9a-f]{64}', 71)
NAME = text(r'[a-z0-9][a-z0-9+_.@-]{0,79}', 80)
VERSION = text(r'[0-9][A-Za-z0-9.+_:~-]{0,95}', 96)


def nullable(validator):
    return lambda value: None if value is None else validator(value)


def sequence(validator, limit):
    def validate(value):
        need(type(value) is list and len(value) <= limit)
        return [validator(item) for item in value]
    return validate


def pick(value, fields):
    need(type(value) is dict)
    return {key: validate(value[key]) for key, validate in fields.items() if key in value}


def hash_map(allowed):
    def validate(value):
        need(type(value) is dict and len(value) <= len(allowed) and set(value) <= allowed)
        return {key: HASH(item) for key, item in sorted(value.items())}
    return validate


def recipe_hashes(value):
    need(type(value) is dict and len(value) <= 128)
    result = {}
    for key, item in value.items():
        need(key in RECIPE_FILES or re.fullmatch(r'icons/cachy-update(?:_updates-available)?-(?:blue|light|dark)(?:-cb)?\.svg', key))
        result[key] = HASH(item)
    return result


def error_count(value):
    need(type(value) is list and len(value) <= 4096 and all(type(item) is str for item in value))
    return len(value)


def receipt(value):
    if 'schema_version' in value:
        need(type(value['schema_version']) is int and value['schema_version'] == 1)
    fields = {'schema_version': integer(1, 1), 'native_pair': enum('STARTING', 'PASS', 'FAIL'),
              'native_compilation': enum('STARTING', 'PASS', 'FAIL', 'NOT RUN', 'FAIL-container-cleanup', 'PASS-private-native-package-static-checks'), 'image_id': IMAGE,
              'inventory_sha256': HASH, 'builder_inventory_sha256': HASH,
              'controller_sha256': HASH, 'entry_script_sha256': HASH, 'package_sha256': HASH,
              'stage': enum(*STAGES), 'failed_stage': nullable(enum(*STAGES)),
              'publication': enum('NOT ACCEPTED'), 'hardware': enum('NOT RUN'), 'M2': enum('NOT RUN'),
              'error_type': enum(*ERROR_TYPES), 'container_cleanup_error_type': enum(*ERROR_TYPES),
              'container_absence_error_type': enum(*ERROR_TYPES),
              'cancelled': boolean, 'cancel_signal': enum('SIGTERM', 'SIGINT', 'SIGHUP'),
              'container_absent': boolean, 'container_cleanup_verified': boolean,
              'worker_launch_attempted': boolean, 'container_cleanup_attempted': boolean,
              'container_removal_succeeded': boolean, 'container_absence_verified': boolean,
              'container_cleanup_complete': boolean,
              'container_cleanup': enum('PASS', 'FAIL', 'NOT RUN')}
    result = pick(value, fields)
    if 'worker_cleanup_errors' in value:
        result['worker_cleanup_errors'] = sequence(lambda row: pick(row, {
            'worker': integer(2, 1), 'error_type': enum(*ERROR_TYPES)}), 2)(value['worker_cleanup_errors'])
    return result


def native_result(value):
    need('native_pair' in value)
    return receipt(value)


def provenance(value):
    need('native_compilation' in value)
    return receipt(value)


def compile_receipt(value):
    result = receipt(value)
    result.update(pick(value, {'input_sha256': hash_map({'manifest', 'lock', 'audit', 'metadata', 'cfg'}),
        'binary_sha256': HASH, 'compiler_output_sha256': HASH, 'compiler_diagnostic_sha256': HASH,
        'elf_inspection_sha256': HASH, 'compilation_units_sha256': HASH,
        'elf_16k_segments': enum('PASS-static; loader NOT RUN')}))
    return result


def cargo_identity(value):
    need(type(value) is str and len(value) <= 512)
    match = re.fullmatch(r'registry\+https://github.com/rust-lang/crates.io-index#([^@]+)@([^@]+)', value)
    if not match:
        match = re.fullmatch(r'path\+file:///tmp/[A-Za-z0-9_./-]+#(arch-update-tray)@(4\.4\.2)', value)
    need(match is not None)
    identity = match[1] + '@' + match[2]
    need(identity in PACKAGE_IDENTITIES)
    return identity


def feature(value):
    need(type(value) is str and value in FEATURE_NAMES)
    return value


def units(value):
    result = pick(value, {'schema_version': integer(1, 1), 'native_runtime': enum('NOT RUN'), 'hardware': enum('NOT RUN')})
    def artifact(row):
        result = pick(row, {'package_id': cargo_identity, 'fresh': boolean,
                            'features': sequence(feature, 2048)})
        if 'target' in row:
            result['target'] = pick(row['target'], {'kind': sequence(enum('bin', 'lib', 'rlib', 'proc-macro', 'custom-build', 'cdylib', 'staticlib', 'dylib'), 8),
                'crate_types': sequence(enum('bin', 'lib', 'rlib', 'proc-macro', 'cdylib', 'staticlib', 'dylib'), 8),
                'edition': enum('2015', '2018', '2021', '2024')})
        return result
    if 'compiler_artifacts' in value:
        result['compiler_artifacts'] = sequence(artifact, 2048)(value['compiler_artifacts'])
    if 'build_script_runs' in value:
        result['build_script_runs'] = sequence(lambda row: pick(row, {'package_id': cargo_identity}), 256)(value['build_script_runs'])
    return result


def inventory(data):
    rows, seen = [], set()
    for line in data.decode('ascii').splitlines():
        parts = line.split(' ')
        need(len(parts) == 2 and len(rows) < 1024)
        name, version = NAME(parts[0]), VERSION(parts[1])
        need(name not in seen and (name, version) in INVENTORY_ROWS)
        seen.add(name)
        rows.append({'name': name, 'version': version})
    return {'schema_version': 1, 'inventory_sha256': hashlib.sha256(data).hexdigest(), 'packages': rows}


def comparison(value):
    result = pick(value, {'installed_contents_equal': boolean, 'pkginfo_equal': boolean, 'bytes_equal': boolean,
                         'publication': enum('NOT ACCEPTED'), 'hardware': enum('NOT RUN')})
    if 'errors' in value:
        result['error_count'] = error_count(value['errors'])
    return result


def acquisition(value):
    result = pick(value, {'schema_version': integer(1, 1), 'acquisition': enum('IN_PROGRESS', 'PASS', 'FAIL'),
                          'signature_authentication': enum('NOT RUN')})
    if 'counts' in value:
        result['counts'] = pick(value['counts'], {name: integer(1024) for name in ('total', 'pass', 'fail', 'pending')})
    if 'inputs' in value:
        need(type(value['inputs']) is dict and len(value['inputs']) <= 1024)
        result['inputs'] = [pick(row, {'status': enum('PENDING', 'PASS', 'FAIL'),
            'expected_sha256': HASH, 'expected_bytes': integer(1024**3),
            'error_type': enum(*ERROR_TYPES), 'http_status': nullable(integer(599, 100))})
            for row in value['inputs'].values()]
        result['inputs'].sort(key=lambda row: row.get('expected_sha256', ''))
    return result


def bootstrap(value):
    return pick(value, {'dockerfile_sha256': HASH, 'inputs_sha256': HASH, 'image_id': IMAGE,
                        'packages_lock_sha256': HASH, 'expected_inventory_sha256': HASH})


def package_validation(value):
    def artifact(row):
        result = pick(row, {'sha256': HASH, 'status': enum('fail', 'artifact-static-pass')})
        if 'errors' in row:
            result['error_count'] = error_count(row['errors'])
        metadata = row.get('metadata', {})
        if '.PKGINFO' in metadata:
            result['package'] = pick(metadata['.PKGINFO'], {'pkgname': sequence(enum('cachy-asahi-update'), 1),
                'pkgver': sequence(enum('4.4.2-1'), 1), 'arch': sequence(enum('aarch64', 'any'), 1),
                'license': sequence(enum('GPL-3.0-or-later', 'MIT', 'Apache-2.0', 'ISC', 'Unicode-3.0'), 8)})
        if 'elf' in row:
            need(type(row['elf']) is dict and len(row['elf']) <= 16)
            result['elf'] = []
            for path, item in sorted(row['elf'].items()):
                need(path == 'usr/lib/arch-update/arch-update-tray')
                checked = pick(item, {'machine': integer(65535), 'load_segments': integer(65535),
                    'page_alignment': enum('not-applicable-relocatable'), 'hardware_status': enum('NOT RUN')})
                checked['member'] = path
                checked['error_count'] = error_count(item.get('errors', []))
                result['elf'].append(checked)
        return result
    result = {'artifacts': sequence(artifact, 2)(value.get('artifacts', []))}
    if 'errors' in value:
        result['error_count'] = error_count(value['errors'])
    return result


def worker(value):
    result = receipt(value)
    result.update(pick(value, {'host': enum(TARGET), 'target': enum(TARGET),
        'rustc_vv_sha256': HASH, 'sha256': hash_map({'manifest', 'lock', 'audit', 'metadata', 'cfg'}),
        'build_script_execution': enum('NOT RUN'), 'tool_sha256': hash_map({'cargo', 'rustc', 'pacman'})}))
    return result


def controller(value):
    return pick(value, {'schema_version': integer(1, 1), 'image_id': IMAGE,
        'builder_inventory_sha256': HASH, 'tool_pins_sha256': HASH,
        'recipe_input_sha256': recipe_hashes, 'entry_script_sha256': HASH})


def tool_pins(value):
    result = pick(value, {'schema_version': integer(1, 1), 'builder_inventory_sha256': HASH})
    if 'tools' in value:
        need(type(value['tools']) is dict and len(value['tools']) <= len(TOOLS))
        result['tools'] = {}
        for path, item in value['tools'].items():
            need(path in {'/usr/bin/' + tool for tool in TOOLS})
            result['tools'][path.rsplit('/', 1)[1]] = HASH(item['sha256'])
    return result


def closure(value):
    result = pick(value, {'schema_version': integer(1, 1), 'status': enum('VALIDATED METADATA SOURCE CLOSURE'),
        'host': enum(TARGET), 'target': enum(TARGET), 'sha256': hash_map({'manifest', 'lock', 'audit', 'metadata', 'cfg'}),
        'supplemental_notice_ledger_sha256': nullable(HASH), 'original_locked_packages': integer(168),
        'selected_registry_packages': integer(167), 'retained_original_lock': boolean,
        'retained_original_all_target_audit': boolean, 'native_compilation': enum('NOT RUN'),
        'license_compatibility': enum('NOT ACCEPTED')})
    if 'selected_nodes' in value:
        result['selected_nodes'] = sequence(lambda row: pick(row, {'id': cargo_identity,
            'features': sequence(feature, 2048), 'host_dependency': boolean, 'custom_build': boolean}), 168)(value['selected_nodes'])
    if 'supplemental_notices' in value:
        result['source_grants'] = sequence(lambda row: pick(row, {'sha256': HASH, 'bytes': integer(8 * 1024**2)}), 512)(value['supplemental_notices'])
    return result


def materializer(value):
    result = pick(value, {'schema_version': integer(1, 1), 'status': enum('RUNNING', 'PASS', 'FAIL', 'CANCELLED'),
        'phase': enum('launch-data-worker', 'fetch-original', 'fetch-registry', 'regenerate-sanitized', 'regenerate-vendor', 'complete'),
        'failure_code': enum('input-validation', 'download-integrity', 'sanitized-reproduction', 'vendor-reproduction', 'cancellation', 'data-worker-failure'),
        'runner_inputs_sha256': HASH, 'source_hashes': hash_map({'original', 'sanitized', 'vendor'}),
        'completed_registry': integer(167), 'native_compilation': enum('NOT RUN'), 'publication': enum('NOT ACCEPTED'),
        'worker_exit_code': integer(255, -255), 'error_type': enum(*ERROR_TYPES),
        'retained_private_bytes': integer(1024**3), 'cleanup_errors': sequence(enum(*ERROR_TYPES), 16)})
    if 'cancel_signal' in value:
        need(type(value['cancel_signal']) is int and value['cancel_signal'] in (2, 15))
        result['cancel_signal'] = value['cancel_signal']
    for key, fields in {
        'downloads': {'count': integer(168), 'bytes': integer(43873283)},
        'regenerated': {'sanitized_sha256': HASH, 'vendor_sha256': HASH, 'vendor_bytes': integer(512 * 1024**2),
                        'registry_sources': integer(167), 'sanitized_tar_sha256': HASH, 'vendor_tar_sha256': HASH},
        'limits': {'wall_seconds': integer(900), 'cpu_seconds': integer(600), 'address_space_bytes': integer(2147483648),
                   'file_bytes': integer(512 * 1024**2), 'download_bytes': integer(43873283), 'retained_bytes': integer(1073741824),
                   'expanded_source_bytes': integer(402653184), 'source_members': integer(200000)},
        'generator': {name: text(r'[0-9]+(?:\.[0-9]+){1,3}(?:(?:[.-])(?:zlib-ng|dev|rc[0-9]+))?', 40)
                      for name in ('python', 'zlib_build', 'zlib_runtime')} | {'transport': enum('gzip-stored-v1')}
    }.items():
        if key in value:
            result[key] = pick(value[key], fields)
    return result


def load(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value)
            value[key] = item
        return value
    value = json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(Invalid()))
    todo, count = [(value, 0)], 0
    while todo:
        item, depth = todo.pop()
        count += 1
        need(count <= NODE_LIMIT and depth <= 32)
        if type(item) in (dict, list):
            todo.extend((part, depth + 1) for part in (item.values() if type(item) is dict else item))
    need(type(value) is dict)
    return value


def directory(path):
    need('..' not in Path(path).parts)
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        need(stat.S_ISDIR(current.lstat().st_mode))
    return path


def read_selected(root, relative):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(root, flags | os.O_DIRECTORY)
    try:
        parts = relative.split('/')
        for part in parts[:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], flags, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= FILE_LIMIT)
            with os.fdopen(file_fd, 'rb', closefd=False) as stream:
                data = stream.read(FILE_LIMIT + 1)
            after = os.fstat(file_fd)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
                                     info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            need(identity(before) == identity(after) and len(data) == before.st_size)
            return data
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def selectors():
    result = [('result.json', 'native-result.json', native_result), ('comparison.json', 'comparison.json', comparison),
              ('acquisition.json', 'acquisition.json', acquisition), ('bootstrap.json', 'bootstrap.json', bootstrap),
              ('packages.lock', 'inventory.json', inventory), ('tool-pins.json', 'tools.json', tool_pins)]
    for number in (1, 2):
        prefix = f'build-{number}'
        result += [(f'{prefix}/provenance.json', f'{prefix}-status.json', provenance),
                   (f'{prefix}/inputs/controller-input.json', f'{prefix}-inputs.json', controller),
                   (f'{prefix}/package-validation.json', f'{prefix}-package.json', package_validation),
                   (f'{prefix}/artifacts/entry-result.json', f'{prefix}-entry.json', receipt)]
        for filename, handler in [('compile-result.json', compile_receipt), ('compilation-units.json', units),
                                  ('worker.json', worker), ('selected-closure.json', closure)]:
            result.append((f'{prefix}/artifacts/target-metadata/{filename}', f'{prefix}-{filename}', handler))
    return result


def project_evidence(raw, output, materialized=None):
    raw, output = directory(raw), Path(os.path.abspath(output))
    directory(output.parent)
    need('..' not in Path(output).parts and raw != output and raw not in output.parents and output not in raw.parents)
    materialized = directory(materialized) if materialized is not None else None
    if materialized:
        need(materialized != output and materialized not in output.parents and output not in materialized.parents)
    output.mkdir(mode=0o700)
    accepted, rejected, missing, input_total, output_total = [], [], [], 0, 0
    selected = [(raw, *row) for row in selectors()]
    if materialized:
        selected.append((materialized, 'materializer-result.json', 'materializer.json', materializer))
    for root, source, target, handler in selected:
        try:
            data = read_selected(root, source)
            input_total += len(data)
            need(input_total <= TOTAL_INPUT_LIMIT)
            result = handler(data if handler is inventory else load(data))
            encoded = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()
            need(output_total + len(encoded) <= TOTAL_OUTPUT_LIMIT - 65536)
            (output / target).write_bytes(encoded)
            output_total += len(encoded)
            accepted.append({'receipt': target, 'sha256': hashlib.sha256(encoded).hexdigest(), 'bytes': len(encoded)})
        except FileNotFoundError:
            missing.append(target)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            rejected.append({'receipt': target, 'reason': 'invalid-schema-or-file'})
    manifest = {'schema_version': 1, 'projection': 'FAIL' if rejected or not accepted else 'PASS',
                'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN', 'accepted': accepted,
                'rejected': rejected, 'missing': missing,
                'retention_policy': {'raw_outputs': 'ephemeral only', 'max_seconds': RETENTION_SECONDS, 'cleanup_execution': 'NOT ATTESTED'},
                'limits': {'input_bytes': TOTAL_INPUT_LIMIT, 'output_bytes': TOTAL_OUTPUT_LIMIT, 'file_bytes': FILE_LIMIT}}
    (output / 'projection.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--materialized', type=Path)
    args = parser.parse_args()
    try:
        record = project_evidence(args.raw, args.output, args.materialized)
    except (OSError, ValueError):
        raise SystemExit('Public projection failed: invalid or overlapping directory paths.')
    print(json.dumps({'projection': record['projection'], 'receipts': len(record['accepted'])}))
    raise SystemExit(0 if record['projection'] == 'PASS' else 1)
