# SPDX-License-Identifier: MIT
add_library(qt612-protocol-server OBJECT)
target_link_libraries(qt612-protocol-server PRIVATE Qt6::Core Wayland::Server)
qt6_generate_wayland_protocol_server_sources(qt612-protocol-server PRIVATE_CODE
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/../desktop-probe.xml)
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/wayland-desktop-probe-protocol.c
    PROPERTIES HEADER_FILE_ONLY ON)
