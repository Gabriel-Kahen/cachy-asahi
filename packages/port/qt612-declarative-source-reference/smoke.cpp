// SPDX-License-Identifier: MIT
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QJSEngine>
#include <QQuickWindow>
#include <QTimer>
#include <QDebug>
int main(int argc,char **argv) {
    QGuiApplication app(argc,argv);
    if (argc!=2) return 2;
    QJSEngine js;
    auto result=js.evaluate("let values=[1,2,3]; values.map(x=>x*x).reduce((a,b)=>a+b,0)");
    if (result.isError() || result.toInt()!=14) return 3;
    QQmlApplicationEngine engine;
    engine.setImportPathList({QStringLiteral(QT612_OWN_QML),QStringLiteral("qrc:/qt/qml")});
    bool failed=false;
    QObject::connect(&engine,&QQmlApplicationEngine::warnings,[&](const QList<QQmlError>& errors){
        for (const auto &e:errors) qCritical()<<e;
        failed=true;
    });
    engine.load(QUrl::fromLocalFile(QString::fromLocal8Bit(argv[1])));
    if (failed || engine.rootObjects().size()!=1) return 4;
    auto *window=qobject_cast<QQuickWindow*>(engine.rootObjects().first());
    if (!window || window->property("answer").toInt()!=42) return 5;
    QTimer::singleShot(500,&app,&QCoreApplication::quit);
    app.exec();
    return failed ? 6 : 0;
}
