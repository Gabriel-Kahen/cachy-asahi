// SPDX-License-Identifier: MIT
// Finite SVG raster/API smoke; no display, GPU, network or hardware claim.
#include <QtCore/QBuffer>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QJsonObject>
#include <QtCore/QPluginLoader>
#include <QtCore/QStringList>
#include <QtCore/QTemporaryDir>
#include <QtCore/QTimer>
#include <QtGui/QIcon>
#include <QtGui/QImage>
#include <QtGui/QImageReader>
#include <QtGui/QPainter>
#include <QtSvg/QSvgGenerator>
#include <QtSvg/QSvgRenderer>
#include <QtSvg/qtsvgversion.h>
#include <QtSvgWidgets/QSvgWidget>
#include <QtSvgWidgets/qtsvgwidgetsversion.h>
#include <QtWidgets/QApplication>
#include <cstdio>
#include <string_view>
#include <sys/stat.h>

static bool ordinaryPlugin(const QString &path)
{
    const QFileInfo file(path);
    struct stat info {};
    return file.isFile() && !file.isSymLink() && file.canonicalFilePath() == path &&
        ::lstat(QFile::encodeName(path).constData(), &info) == 0 &&
        S_ISREG(info.st_mode) && info.st_nlink == 1;
}

static bool pattern(const QImage &image, int extent, bool transparent = true)
{
    return image.size() == QSize(extent, extent) &&
        image.pixelColor(extent / 4, extent / 2) == QColor(211, 31, 47) &&
        image.pixelColor(3 * extent / 4, extent / 2) == QColor(17, 173, 89) &&
        (!transparent || (qAlpha(image.pixel(0, 0)) == 0 &&
                          qAlpha(image.pixel(extent - 1, extent - 1)) == 0));
}

static QImage raster(QSvgRenderer &renderer)
{
    QImage image(32, 32, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);
    QPainter painter(&image);
    renderer.render(&painter);
    painter.end();
    return image;
}

int main(int argc, char **argv)
{
    static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0));
    static_assert(std::string_view(QTSVG_VERSION_STR) == "6.12.0");
    static_assert(std::string_view(QTSVGWIDGETS_VERSION_STR) == "6.12.0");
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    if (QString::fromLatin1(qVersion()) != QStringLiteral("6.12.0") ||
        app.platformName() != QStringLiteral("offscreen"))
        return 1;
    const QString ownRoot = qEnvironmentVariable("QT612_OWN_PLUGIN_ROOT");
    const QFileInfo root(ownRoot);
    if (ownRoot != QString::fromUtf8(QT612_EXPECTED_PLUGIN_ROOT) ||
        !root.isAbsolute() || !root.isDir() || root.canonicalFilePath() != ownRoot)
        return 9;
    const QString imagePlugin = ownRoot + QStringLiteral("/imageformats/libqsvg.so");
    const QString iconPlugin = ownRoot + QStringLiteral("/iconengines/libqsvgicon.so");
    if (!ordinaryPlugin(imagePlugin) || !ordinaryPlugin(iconPlugin))
        return 9;
    // The base offscreen platform has loaded; SVG discovery now has only our root.
    QCoreApplication::setLibraryPaths(QStringList{ownRoot});
    if (QCoreApplication::libraryPaths() != QStringList{ownRoot})
        return 9;
    QPluginLoader imageLoader(imagePlugin);
    QPluginLoader iconLoader(iconPlugin);
    if (imageLoader.metaData().value(QStringLiteral("IID")).toString() !=
            QStringLiteral("org.qt-project.Qt.QImageIOHandlerFactoryInterface") ||
        iconLoader.metaData().value(QStringLiteral("IID")).toString() !=
            QStringLiteral("org.qt-project.Qt.QIconEngineFactoryInterface") ||
        !imageLoader.instance() || !iconLoader.instance())
        return 9;
    const QByteArray svg(R"SVG(<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32"><rect x="4" y="4" width="12" height="24" fill="#d31f2f"/><rect x="16" y="4" width="12" height="24" fill="#11ad59"/></svg>)SVG");
    QSvgRenderer renderer;
    if (!renderer.load(svg) || !renderer.isValid() || renderer.animated() ||
        renderer.defaultSize() != QSize(32, 32) || !pattern(raster(renderer), 32))
        return 2;

    QByteArray generated;
    QBuffer output(&generated);
    if (!output.open(QIODevice::WriteOnly))
        return 3;
    {
        QSvgGenerator generator;
        generator.setOutputDevice(&output);
        generator.setSize(QSize(32, 32));
        generator.setViewBox(QRect(0, 0, 32, 32));
        generator.setResolution(96);
        QPainter painter;
        if (!painter.begin(&generator))
            return 3;
        painter.fillRect(QRect(4, 4, 24, 24), QColor(17, 31, 211));
        if (!painter.end())
            return 3;
    }
    output.close();
    QSvgRenderer roundtrip;
    if (generated.isEmpty() || generated.size() > 65536 || !roundtrip.load(generated) ||
        !roundtrip.isValid() || roundtrip.viewBox() != QRect(0, 0, 32, 32))
        return 4;
    const QImage regenerated = raster(roundtrip);
    if (regenerated.pixelColor(16, 16) != QColor(17, 31, 211) ||
        qAlpha(regenerated.pixel(0, 0)) != 0)
        return 4;

    QSvgWidget widget;
    widget.load(svg);
    widget.resize(32, 32);
    if (!widget.renderer()->isValid())
        return 5;
    QImage widgetImage(32, 32, QImage::Format_ARGB32_Premultiplied);
    widgetImage.fill(Qt::transparent);
    widget.render(&widgetImage);
    if (!pattern(widgetImage, 32, false))
        return 5;

    if (!QImageReader::supportedImageFormats().contains(QByteArray("svg")))
        return 6;
    QBuffer input;
    input.setData(svg);
    if (!input.open(QIODevice::ReadOnly))
        return 6;
    QImageReader reader(&input, QByteArray("svg"));
    if (!reader.canRead() || !pattern(reader.read(), 32))
        return 6;

    QTemporaryDir temporary;
    if (!temporary.isValid())
        return 7;
    const QString svgPath = temporary.filePath(QStringLiteral("smoke.svg"));
    QFile file(svgPath);
    if (!file.open(QIODevice::WriteOnly) || file.write(svg) != svg.size() || !file.flush())
        return 7;
    file.close();
    QIcon icon(svgPath);
    // Request twice the source size: require scalable SVG engine rendering.
    const QImage iconImage = icon.pixmap(QSize(64, 64), 1.0, QIcon::Normal, QIcon::Off).toImage();
    if (icon.isNull() || !pattern(iconImage, 64))
        return 8;

    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    const int result = app.exec();
    if (result == 0)
        std::puts("PASS_QT612_SVG_OFFSCREEN_API_RENDER_ONLY");
    return result;
}
