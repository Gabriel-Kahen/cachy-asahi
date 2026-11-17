// SPDX-License-Identifier: MIT
// Own-built Qt API/offscreen smoke only; no display or Apple hardware claim.
#include <QtCore/QCryptographicHash>
#include <QtCore/QTemporaryFile>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtGui/QImage>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
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
    const QByteArray payload("Qt 6.12.0 source reference\n");
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
    widget.show();
    QImage image(widget.size(), QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);
    widget.render(&image);
    if (image.isNull() || qAlpha(image.pixel(16, 16)) == 0)
        return 4;
    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    const int result = app.exec();
    if (result == 0)
        std::puts("PASS_QT612_OFFSCREEN_API_SMOKE_ONLY");
    return result;
}
