// SPDX-License-Identifier: MIT
// Only Rectangle/Image objects are created; compositor imports register types.
import QtQuick 6.12
import QtWayland.Compositor 6.12
import QtWayland.Compositor.XdgShell 6.12
import QtWayland.Compositor.IviApplication 6.12
import QtWayland.Compositor.WlShell 6.12
import QtWayland.Compositor.QtShell 6.12
import QtWayland.Compositor.PresentationTime 6.12
import QtWayland.Compositor.TextureSharingExtension 6.12

Rectangle {
    width: 32
    height: 32
    color: "#102030"
    readonly property bool assetReady: svg.status === Image.Ready
    Image {
        id: svg
        x: 8
        y: 8
        width: 16
        height: 16
        source: "colors.svg"
        sourceSize: Qt.size(16, 16)
        asynchronous: false
        cache: false
        smooth: false
        mipmap: false
        fillMode: Image.Stretch
    }
}
