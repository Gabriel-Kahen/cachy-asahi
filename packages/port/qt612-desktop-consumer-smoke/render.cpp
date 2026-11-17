// SPDX-License-Identifier: MIT
// Installed Qt6.12 software/SVG consumer. No compositor, visible window or GPU.
#include <QtCore/QLibraryInfo>
#include <QtCore/QUrl>
#include <QtCore/QVariant>
#include <QtGui/QColor>
#include <QtGui/QGuiApplication>
#include <QtGui/QImageReader>
#include <QtGui/QPainter>
#include <QtQml/QQmlComponent>
#include <QtQml/QQmlEngine>
#include <QtQml/qqml.h>
#include <QtQuick/QQuickItem>
#include <QtQuick/QQuickRenderControl>
#include <QtQuick/QQuickRenderTarget>
#include <QtQuick/QQuickWindow>
#include <QtQuick/QSGRendererInterface>
#include <QtSvg/QSvgRenderer>
#include <QtWaylandCompositor/QWaylandCompositor>
#include <cstdio>
#include <memory>

static int fail(int code, const char *reason)
{
    std::fprintf(stderr, "Qt6.12 desktop consumer: %s\n", reason);
    return code;
}

static bool canvasPixels(const QImage &image)
{
    if (image.size() != QSize(32, 32))
        return false;
    const struct { int x, y; QRgb color; } samples[] = {
        {2, 2, qRgb(16, 32, 48)}, {29, 29, qRgb(16, 32, 48)},
        {7, 16, qRgb(16, 32, 48)}, {24, 16, qRgb(16, 32, 48)},
        {10, 10, qRgb(224, 32, 48)}, {14, 20, qRgb(224, 32, 48)},
        {18, 10, qRgb(32, 64, 208)}, {22, 20, qRgb(32, 64, 208)},
    };
    for (const auto &sample : samples)
        if (image.pixelColor(sample.x, sample.y).rgba() != sample.color)
            return false;
    return true;
}

int main(int argc, char **argv)
{
    static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0));
    if (QStringLiteral(QT612_PLUGIN_DIR) != QStringLiteral("/usr/lib/qt6/plugins") ||
        QStringLiteral(QT612_QML_DIR) != QStringLiteral("/usr/lib/qt6/qml"))
        return fail(1, "installed dependency paths must be explicit /usr paths");
    qputenv("QT_QPA_PLATFORM", "offscreen");
    qputenv("QT_QPA_PLATFORM_PLUGIN_PATH", QByteArray(QT612_PLUGIN_DIR "/platforms"));
    qputenv("QT_QUICK_BACKEND", "software");
    qputenv("QT_SCALE_FACTOR", "1");
    QCoreApplication::setLibraryPaths({QStringLiteral(QT612_PLUGIN_DIR)});
    QGuiApplication app(argc, argv);
    QCoreApplication::setLibraryPaths({QStringLiteral(QT612_PLUGIN_DIR)});
    if (QString::fromLatin1(qVersion()) != QStringLiteral("6.12.0") ||
        QLibraryInfo::path(QLibraryInfo::PrefixPath) != QStringLiteral("/usr") ||
        app.platformName() != QStringLiteral("offscreen"))
        return fail(2, "runtime must be installed Qt6.12.0 with offscreen QPA");

    const QString svgPath = QStringLiteral(":/qt612-desktop/colors.svg");
    QImageReader reader(svgPath, "svg");
    if (!reader.canRead() || reader.format() != "svg" || reader.size() != QSize(16, 16))
        return fail(3, "SVG image-format plugin cannot read the fixed asset");
    const QImage decoded = reader.read();
    if (decoded.size() != QSize(16, 16) || decoded.pixelColor(4, 8) != QColor(224, 32, 48) ||
        decoded.pixelColor(12, 8) != QColor(32, 64, 208))
        return fail(4, "SVG plugin interior pixels differ");

    QSvgRenderer svg(svgPath);
    QImage painted(32, 32, QImage::Format_ARGB32_Premultiplied);
    painted.fill(QColor(16, 32, 48));
    QPainter painter(&painted);
    if (!svg.isValid() || svg.defaultSize() != QSize(16, 16) || !painter.isActive())
        return fail(5, "SVG painter setup failed");
    svg.render(&painter, QRectF(8, 8, 16, 16));
    if (!painter.end() || !canvasPixels(painted))
        return fail(6, "QSvgRenderer/QPainter interior pixels differ");

    QQuickWindow::setGraphicsApi(QSGRendererInterface::Software);
    QImage frame(32, 32, QImage::Format_ARGB32_Premultiplied);
    frame.fill(Qt::transparent);
    frame.setDevicePixelRatio(1);
    QQuickRenderControl control;
    QQuickWindow window(&control);
    window.setGeometry(0, 0, 32, 32);
    window.setRenderTarget(QQuickRenderTarget::fromPaintDevice(&frame));
    QQmlEngine engine;
    engine.setImportPathList({QStringLiteral(QT612_QML_DIR), QStringLiteral("qrc:/qt-project.org/imports")});
    QQmlComponent component(&engine);
    component.loadUrl(QUrl(QStringLiteral("qrc:/qt612-desktop/Scene.qml")), QQmlComponent::PreferSynchronous);
    if (!component.isReady()) {
        for (const auto &error : component.errors())
            std::fprintf(stderr, "%s\n", qPrintable(error.toString()));
        return fail(7, "fixed QML scene or compositor imports failed");
    }
    const struct { const char *uri, *name; } types[] = {
        {"QtWayland.Compositor", "WaylandCompositor"},
        {"QtWayland.Compositor.XdgShell", "XdgShell"},
        {"QtWayland.Compositor.IviApplication", "IviApplication"},
        {"QtWayland.Compositor.WlShell", "WlShell"},
        {"QtWayland.Compositor.QtShell", "QtShell"},
        {"QtWayland.Compositor.PresentationTime", "PresentationTime"},
        {"QtWayland.Compositor.TextureSharingExtension", "TextureSharingExtension"},
    };
    for (const auto &type : types)
        if (qmlTypeId(type.uri, 6, 12, type.name) < 0)
            return fail(8, "compositor QML type registration failed");
    if (QByteArray(QWaylandCompositor::staticMetaObject.className()) != "QWaylandCompositor")
        return fail(9, "compositor public library symbol differs");
    std::unique_ptr<QObject> object(component.create());
    auto *root = qobject_cast<QQuickItem *>(object.get());
    if (!root || root->size() != QSizeF(32, 32) || !root->property("assetReady").toBool())
        return fail(10, "QML Rectangle/Image scene is not ready");
    root->setParentItem(window.contentItem());
    // Qt6.12 software adaptation explicitly forbids render-control initialize().
    control.polishItems();
    if (!control.sync() || !window.rendererInterface() ||
        window.rendererInterface()->graphicsApi() != QSGRendererInterface::Software)
        return fail(11, "software scenegraph synchronization failed");
    control.render();
    if (!canvasPixels(frame))
        return fail(12, "Qt Quick software SVG/image interior pixels differ");
    std::puts("PASS_QT612_DESKTOP_SOFTWARE_SVG_QML_PIXELS_ONLY");
    return 0;
}
