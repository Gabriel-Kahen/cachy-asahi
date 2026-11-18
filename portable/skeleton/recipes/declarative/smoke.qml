// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts as Layouts
import QtCore as Audit0
import QtQuick.Effects as Audit1
import QtQuick.tooling as Audit2
import Qt.labs.animation as Audit3
import Qt.labs.folderlistmodel as Audit4
import Qt.labs.qmlmodels as Audit5
import Qt.labs.platform as Audit6
import Qt.labs.settings as Audit7
import Qt.labs.sharedimage as Audit8
import Qt.labs.StyleKit as Audit9
import Qt.labs.StyleKit.impl as Audit10
import Qt.labs.synchronizer as Audit11
import Qt.labs.wavefrontmesh as Audit12
import QtQuick.Particles as Audit13
import QML as Audit14
import QtQml.DesignSupport as Audit15
import QtQuick.LocalStorage as Audit16
import QtQml as Audit17
import QtQml.Models as Audit18
import QtNetwork as Audit19
import QtTest as Audit20
import QtQml.WorkerScript as Audit21
import QtQml.XmlListModel as Audit22
import QtQuick.Window as Audit24
import QtQuick.Controls.Basic as Audit26
import QtQuick.Controls.Basic.impl as Audit27
import QtQuick.Controls.FluentWinUI3 as Audit28
import QtQuick.Controls.FluentWinUI3.impl as Audit29
import QtQuick.Controls.Fusion as Audit30
import QtQuick.Controls.Fusion.impl as Audit31
import QtQuick.Controls.Imagine as Audit32
import QtQuick.Controls.Imagine.impl as Audit33
import QtQuick.Controls.Material as Audit34
import QtQuick.Controls.Material.impl as Audit35
import QtQuick.Controls.Universal as Audit36
import QtQuick.Controls.Universal.impl as Audit37
import QtQuick.Controls.impl as Audit38
import QtQuick.Dialogs as Audit39
import QtQuick.Dialogs.quickimpl as Audit40
import QtQuick.Shapes as Audit42
import QtQuick.Shapes.DesignHelpers as Audit43
import QtQuick.Templates as Audit44
import QtQuick.VectorImage as Audit45
import QtQuick.VectorImage.Helpers as Audit46
Controls.ApplicationWindow {
    width: 160; height: 120; visible: true
    property int answer: 42
    Layouts.ColumnLayout {
        anchors.fill: parent
        Controls.Label { text: "QML/Quick" }
        Controls.Button { text: "Controls"; onClicked: parent.parent.answer = 43 }
        Repeater { model: [1, 2]; delegate: Rectangle { required property int modelData; width: modelData; height: 2 } }
    }
}
