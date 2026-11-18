// SPDX-License-Identifier: MIT
// Offscreen API/type registration and QML compilation only; no compositor.
#include <QtCore/QFileInfo>
#include <QtCore/QUrl>
#include <QtDBus/QDBusMessage>
#include <QtGui/QGuiApplication>
#include <QtOpenGL/QOpenGLVersionProfile>
#include <QtQml/QQmlComponent>
#include <QtQml/QQmlEngine>
#include <QtQml/qqml.h>
#include <QtQuick/QQuickItem>
#include <QtSvg/QSvgRenderer>
#include <QtWaylandClient/QWaylandClientExtension>
#include <QtWaylandCompositor/QWaylandCompositor>
#include <cstdio>

int main(int argc, char **argv)
{
    static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0));
    if (argc != 2 || !QFileInfo(QString::fromLocal8Bit(argv[1])).isAbsolute())
        return 1;
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QGuiApplication app(argc, argv);
    if (QString::fromLatin1(qVersion()) != QStringLiteral("6.12.0") ||
        app.platformName() != QStringLiteral("offscreen"))
        return 2;
    if (QByteArray(QWaylandCompositor::staticMetaObject.className()) != "QWaylandCompositor" ||
        QByteArray(QWaylandClientExtension::staticMetaObject.className()) != "QWaylandClientExtension" ||
        QByteArray(QQuickItem::staticMetaObject.className()) != "QQuickItem")
        return 3;
    QOpenGLVersionProfile profile;
    profile.setVersion(3, 3);
    if (!profile.isValid() || profile.version().first != 3)
        return 4;
    QSvgRenderer svg(QByteArray("<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>"));
    const auto message = QDBusMessage::createSignal("/qt612/smoke", "org.qtproject.Qt612Smoke", "probe");
    if (!svg.isValid() || message.type() != QDBusMessage::SignalMessage)
        return 5;
    QQmlEngine engine;
    // Replace default/environment/user paths with the two selected local roots.
    engine.setImportPathList({QStringLiteral(QT612_WAYLAND_QML_DIR), QStringLiteral(QT612_DEPENDENCY_QML_DIR)});
    QQmlComponent component(&engine);
    component.loadUrl(QUrl::fromLocalFile(QString::fromLocal8Bit(argv[1])), QQmlComponent::PreferSynchronous);
    if (!component.isReady()) {
        for (const auto &error : component.errors())
            std::fprintf(stderr, "%s\n", qPrintable(error.toString()));
        return 6;
    }
    const struct { const char *uri; const char *type; } types[] = {
        {"QtWayland.Compositor", "WaylandCompositor"},
        {"QtWayland.Compositor.XdgShell", "XdgShell"},
        {"QtWayland.Compositor.IviApplication", "IviApplication"},
        {"QtWayland.Compositor.WlShell", "WlShell"},
        {"QtWayland.Compositor.QtShell", "QtShell"},
        {"QtWayland.Compositor.PresentationTime", "PresentationTime"},
        {"QtWayland.Compositor.TextureSharingExtension", "TextureSharingExtension"},
    };
    for (const auto &type : types)
        if (qmlTypeId(type.uri, 6, 12, type.type) < 0)
            return 7;
    // No component.create(), compositor.create(), socket or graphics context.
    std::puts("PASS_QT612_WAYLAND_QML_API_ONLY");
    return 0;
}
