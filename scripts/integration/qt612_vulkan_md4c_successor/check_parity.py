#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the expected parity files and linkage in the Qtbase stage report."""

import json
from pathlib import Path
import sys


GUI_PRIVATE = "usr/include/qt6/QtGui/6.12.0/QtGui/private/"
PRINT_PRIVATE = "usr/include/qt6/QtPrintSupport/6.12.0/QtPrintSupport/private/"
PLUGINS = {
    "usr/lib/qt6/plugins/printsupport/libcupsprintersupport.so": "libcups.so.2",
    "usr/lib/qt6/plugins/xcbglintegrations/libqxcb-egl-integration.so": "libEGL.so.1",
}
CMAKE_EXPORTS = (
    "Qt6Gui/Qt6QXcbEglIntegrationPlugin",
    "Qt6PrintSupport/Qt6QCupsPrinterSupportPlugin",
)
ADDED_FILES = {
    *(GUI_PRIVATE + header for header in (
        "atspiadaptor_p.h", "bus_interface_p.h", "cache_adaptor_p.h", "dbusconnection_p.h",
        "deviceeventcontroller_adaptor_p.h", "properties_interface_p.h", "qspi_constant_mappings_p.h",
        "qspi_struct_marshallers_p.h", "qspiaccessiblebridge_p.h",
        "qspiapplicationadaptor_p.h", "qspidbuscache_p.h", "qspimatchrulematcher_p.h", "socket_interface_p.h",
    )),
    PRINT_PRIVATE + "qcups_p.h",
    PRINT_PRIVATE + "qcupsjobwidget_p.h",
    *(f"usr/lib/cmake/{target}{suffix}.cmake" for target in CMAKE_EXPORTS for suffix in (
        "AdditionalTargetInfo", "Config", "ConfigVersion", "ConfigVersionImpl",
        "Targets-release", "Targets", "TargetsPrecheck",
    )),
    *PLUGINS,
}


def check_parity(stage):
    files, elf = stage["files"], stage["elf"]
    missing = ADDED_FILES - files.keys()
    if missing:
        raise ValueError("Qt parity files missing: " + ", ".join(sorted(missing)))
    for plugin, library in PLUGINS.items():
        dynamic = elf.get(plugin, {})
        if dynamic.get("type") != 3 or not files[plugin]["mode"] & 0o111 or library not in dynamic.get("needed", ()):
            raise ValueError(f"Qt parity plugin must be an executable ELF shared object linked to {library}: {plugin}")


if __name__ == "__main__":
    try:
        check_parity(json.loads(Path(sys.argv[1]).read_bytes()))
    except (KeyError, OSError, ValueError) as error:
        sys.exit(str(error))
