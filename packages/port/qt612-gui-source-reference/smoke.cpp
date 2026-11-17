// SPDX-License-Identifier: MIT
// Finite offscreen raster/API smoke; no GL context, display or hardware claim.
#include <QtCore/QCryptographicHash>
#include <QtCore/QTemporaryFile>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtGui/QImage>
#include <QtGui/QPalette>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
#include <QtOpenGL/QOpenGLVersionProfile>
#include <QtOpenGLWidgets/QOpenGLWidget>
#include <QtPrintSupport/QPageSetupDialog>
#include <QtWaylandClient/QWaylandClientExtension>
#include <QtWidgets/QApplication>
#include <QtWidgets/QWidget>
#include <cstdio>

int main(int argc, char **argv)
{
    static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0));
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    if (QString::fromLatin1(qVersion()) != QStringLiteral("6.12.0") ||
        app.platformName() != QStringLiteral("offscreen"))
        return 1;
    const QByteArray payload("Qt 6.12.0 GUI source reference\n");
    QTemporaryFile file;
    if (!file.open() || file.write(payload) != payload.size() || !file.seek(0) ||
        file.readAll() != payload || QCryptographicHash::hash(payload, QCryptographicHash::Sha256).size() != 32)
        return 2;
    QNetworkAccessManager manager;
    QNetworkRequest request(QUrl(QStringLiteral("https://example.invalid/")));
    request.setRawHeader("X-Qt-Smoke", "6.12.0");
    if (manager.thread() != app.thread() || request.rawHeader("X-Qt-Smoke") != "6.12.0")
        return 3;
    QWidget widget;
    widget.resize(32, 32);
    const QColor background(17, 31, 47);
    QPalette palette = widget.palette();
    palette.setColor(QPalette::Window, background);
    widget.setPalette(palette);
    widget.setAutoFillBackground(true);
    widget.show();
    QImage image(widget.size(), QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);
    widget.render(&image);
    if (image.isNull() || image.pixelColor(16, 16) != background)
        return 4;
    QOpenGLVersionProfile profile;
    profile.setVersion(3, 3);
    profile.setProfile(QSurfaceFormat::CoreProfile);
    if (!profile.isValid() || profile.version().first != 3 || profile.version().second != 3 ||
        profile.profile() != QSurfaceFormat::CoreProfile)
        return 5;
    // Link public modules without a GL context, printer dialog or compositor.
    if (QByteArray(QOpenGLWidget::staticMetaObject.className()) != "QOpenGLWidget" ||
        QByteArray(QPageSetupDialog::staticMetaObject.className()) != "QPageSetupDialog" ||
        QByteArray(QWaylandClientExtension::staticMetaObject.className()) != "QWaylandClientExtension")
        return 6;
    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    const int result = app.exec();
    if (result == 0)
        std::puts("PASS_QT612_GUI_OFFSCREEN_WIDGETS_OPENGL_API_ONLY");
    return result;
}
