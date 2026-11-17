# SPDX-License-Identifier: MIT
# Project-specific include after project() enables languages; never bypass Qt ABI checks.
if(QT_NO_PACKAGE_VERSION_CHECK)
    message(FATAL_ERROR "Qt dependency version checks cannot be disabled")
endif()
if(NOT QT612_DEPENDENCY_PREFIX STREQUAL "/usr")
    message(FATAL_ERROR "An explicitly selected /usr Qt dependency prefix is required")
endif()
set(CMAKE_FIND_USE_PACKAGE_REGISTRY OFF)
set(CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY OFF)
set(Qt6_DIR "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6" CACHE PATH "" FORCE)
foreach(_module BuildInternals Core Gui DBus OpenGL Qml Quick Svg WaylandClient)
    set(Qt6${_module}_DIR "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6${_module}" CACHE PATH "" FORCE)
endforeach()
find_package(Qt6 6.12.0 EXACT REQUIRED CONFIG
    COMPONENTS BuildInternals Core Gui DBus OpenGL Qml Quick Svg WaylandClient
    PATHS "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6" NO_DEFAULT_PATH)
find_package(Qt6QmlBuildInternals 6.12.0 EXACT REQUIRED CONFIG
    PATHS "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6QmlBuildInternals" NO_DEFAULT_PATH)
find_package(Qt6WaylandScannerTools 6.12.0 EXACT REQUIRED CONFIG
    PATHS "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6WaylandScannerTools" NO_DEFAULT_PATH)
foreach(_module Core Gui DBus OpenGL Qml Quick Svg WaylandClient)
    if(NOT Qt6${_module}_DIR STREQUAL "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6${_module}" OR
       NOT TARGET Qt6::${_module})
        message(FATAL_ERROR "Matching normal Qt6.12 ${_module} provider is required")
    endif()
    get_target_property(_version Qt6::${_module} _qt_package_version)
    if(NOT _version STREQUAL "6.12.0")
        message(FATAL_ERROR "Refusing mismatched private/public Qt dependency ABI")
    endif()
endforeach()
foreach(_target Qt6::CorePrivate Qt6::GuiPrivate Qt6::QmlPrivate Qt6::QuickPrivate
                Qt6::WaylandClientPrivate Qt6::WaylandGlobalPrivate Qt6::qtwaylandscanner)
    if(NOT TARGET ${_target})
        message(FATAL_ERROR "Required Qt private/scanner target is missing: ${_target}")
    endif()
endforeach()
foreach(_feature wayland waylandscanner wayland_client wayland_egl opengl egl wayland_server)
    if(NOT "${QT_FEATURE_${_feature}}" STREQUAL "ON" AND
       NOT "${QT_FEATURE_${_feature}}" STREQUAL "1")
        message(FATAL_ERROR "Required imported Qtbase feature is unavailable: ${_feature}; frozen GUI18 server-OFF is insufficient")
    endif()
endforeach()
if(NOT EXISTS "${QT612_DEPENDENCY_PREFIX}/lib/qt6/qtwaylandscanner")
    message(FATAL_ERROR "The matching own Qt6 scanner must be installed; Qt5 is not a substitute")
endif()
