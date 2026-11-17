// SPDX-License-Identifier: MIT
#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QDebug>
#include <rhi/qshaderbaker.h>
#include <rhi/qshader.h>
#include <QtShaderTools/private/qspirvcompiler_p.h>
#include <cstring>

static QShader readShader(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size()<=0 || file.size()>1024*1024) return {};
    return QShader::fromSerialized(file.readAll());
}
static bool exercise(const char *source, QShader::Stage stage, const char *compiled) {
    QShaderBaker baker;
    baker.setSourceFileName(QString::fromLocal8Bit(source), stage);
    const QList<QShaderBaker::GeneratedShader> requested={{QShader::SpirvShader,QShaderVersion(100)},
        {QShader::GlslShader,QShaderVersion(100,QShaderVersion::GlslEs)},
        {QShader::GlslShader,QShaderVersion(120)}, {QShader::GlslShader,QShaderVersion(150)},
        {QShader::HlslShader,QShaderVersion(50)}, {QShader::MslShader,QShaderVersion(12)}};
    baker.setGeneratedShaders(requested);
    baker.setGeneratedShaderVariants(stage==QShader::VertexStage ?
        QList<QShader::Variant>{QShader::StandardShader,QShader::BatchableVertexShader} :
        QList<QShader::Variant>{QShader::StandardShader});
    const QShader baked=baker.bake();
    if (!baked.isValid() || baked.stage()!=stage || baked.availableShaders().size()<(stage==QShader::VertexStage?12:6)) {
        qCritical()<<baker.errorMessage(); return false;
    }
    for (const auto &request:requested) {
        if (baked.shader(QShaderKey(request.first,request.second,QShader::StandardShader)).shader().isEmpty()) return false;
        if (stage==QShader::VertexStage && baked.shader(QShaderKey(request.first,request.second,QShader::BatchableVertexShader)).shader().isEmpty()) return false;
    }
    const QShader read=readShader(QString::fromLocal8Bit(compiled));
    const QShader roundtrip=QShader::fromSerialized(baked.serialized());
    if (!read.isValid() || read.stage()!=stage || !roundtrip.isValid()
        || roundtrip.description()!=baked.description() || read.description()!=baked.description()) return false;
    const auto generated=readShader(stage==QShader::VertexStage ?
        QStringLiteral(":/finite/smoke.vert.qsb") : QStringLiteral(":/finite/smoke.frag.qsb"));
    if (stage==QShader::VertexStage) {
        QSpirvCompiler compiler;
        compiler.setSourceFileName(QString::fromLocal8Bit(source),stage);
        if (compiler.compileToSpirv().size()<20) return false;
    }
    return generated.isValid() && generated.stage()==stage && generated.description()==baked.description();
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    if (argc!=5 || std::strcmp(qVersion(),"6.12.0")!=0) return 2;
    return exercise(argv[1],QShader::VertexStage,argv[3]) && exercise(argv[2],QShader::FragmentStage,argv[4]) ? 0 : 3;
}
