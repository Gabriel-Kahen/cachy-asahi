# SPDX-License-Identifier: MIT
# Extra normal server prerequisite: Qtbase's feature itself checks only client/scanner.
find_package(PkgConfig REQUIRED)
pkg_check_modules(QT612Server REQUIRED IMPORTED_TARGET wayland-server>=1.15)
include(CMakePushCheckState)
include(CheckCXXSourceCompiles)
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_LIBRARIES PkgConfig::QT612Server)
check_cxx_source_compiles("#include <wayland-server-core.h>
int main() { auto *display = wl_display_create();
  if (!display) return 1; wl_display_destroy(display); return 0; }"
  QT612_SERVER_API_LINKS)
cmake_pop_check_state()
if(NOT QT612_SERVER_API_LINKS)
    message(FATAL_ERROR "The normal Wayland server headers/library must link")
endif()
set(QT612_SERVER_PC_VERSION "${QT612Server_VERSION}" CACHE INTERNAL "Audited server pkg-config version" FORCE)
