# SPDX-License-Identifier: MIT
add_library(qt612-protocol-client OBJECT)
target_link_libraries(qt612-protocol-client PRIVATE Qt6::Core Wayland::Client)
qt6_generate_wayland_protocol_client_sources(qt612-protocol-client PRIVATE_CODE
    FILES ${CMAKE_CURRENT_SOURCE_DIR}/../desktop-probe.xml)
