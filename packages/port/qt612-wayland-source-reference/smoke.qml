// SPDX-License-Identifier: MIT
// Compiled only. The C++ probe never instantiates this root or a compositor.
import QtQml 6.12
import QtQuick 6.12
import QtWayland.Compositor 6.12
import QtWayland.Compositor.XdgShell 6.12
import QtWayland.Compositor.IviApplication 6.12
import QtWayland.Compositor.WlShell 6.12
import QtWayland.Compositor.QtShell 6.12
import QtWayland.Compositor.PresentationTime 6.12
import QtWayland.Compositor.TextureSharingExtension 6.12

QtObject {
    readonly property string evidenceScope: "QML_COMPILE_AND_REGISTRATION_ONLY"
}
