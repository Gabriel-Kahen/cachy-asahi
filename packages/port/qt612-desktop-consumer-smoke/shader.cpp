// SPDX-License-Identifier: MIT
// Installed qsb/CMake consumer: deserialize and reflect bytes, never render.
#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <rhi/qshader.h>
#include <rhi/qshaderdescription.h>
#include <cstdio>
#include <cstring>

static bool variable(const QList<QShaderDescription::InOutVariable> &variables,
                     int location, QShaderDescription::VariableType type, const char *name)
{
    for (const auto &value : variables)
        if (value.location == location && value.type == type && value.name == name)
            return true;
    return false;
}

static int fail(const char *message)
{
    qCritical("Shader consumer: %s", message);
    return 1;
}

int main(int argc, char **argv)
{
    static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0));
    QCoreApplication app(argc, argv);
    if (std::strcmp(qVersion(), "6.12.0") != 0)
        return fail("Qt6.12.0 runtime required");
    QFile file(QStringLiteral(":/qt612-desktop/probe.vert.qsb"));
    if (!file.open(QIODevice::ReadOnly) || file.size() <= 0 || file.size() > 4 * 1024 * 1024)
        return fail("bounded qt_add_shaders resource required");
    const QByteArray serialized = file.readAll();
    if (serialized.size() != file.size())
        return fail("complete serialized resource required");
    const QShader shader = QShader::fromSerialized(serialized);
    if (!shader.isValid() || shader.stage() != QShader::VertexStage)
        return fail("valid serialized vertex shader required");
    bool spirv = false;
    for (const auto &key : shader.availableShaders())
        if (key.source() == QShader::SpirvShader && key.sourceVariant() == QShader::StandardShader
                && !shader.shader(key).shader().isEmpty())
            spirv = true;
    if (!spirv)
        return fail("nonempty standard SPIR-V output required");
    const QShaderDescription description = shader.description();
    const auto inputs = description.inputVariables();
    const auto outputs = description.outputVariables();
    if (!description.isValid() || inputs.size() != 2 || outputs.size() != 1
            || !variable(inputs, 0, QShaderDescription::Vec3, "position")
            || !variable(inputs, 1, QShaderDescription::Vec4, "color")
            || !variable(outputs, 0, QShaderDescription::Vec4, "vertexColor"))
        return fail("exact input/output reflection required");
    const auto blocks = description.uniformBlocks();
    if (blocks.size() != 1)
        return fail("one uniform block required");
    const auto &block = blocks.front();
    if (block.blockName != "Params" || block.structName != "params" || block.binding != 0
            || block.descriptorSet != 0 || block.size != 80 || block.members.size() != 2)
        return fail("Params std140 binding/size reflection required");
    const auto &transform = block.members[0];
    const auto &tint = block.members[1];
    if (transform.name != "transform" || transform.type != QShaderDescription::Mat4
            || transform.offset != 0 || transform.size != 64 || transform.matrixStride != 16
            || transform.matrixIsRowMajor || !transform.arrayDims.isEmpty()
            || tint.name != "tint" || tint.type != QShaderDescription::Vec4
            || tint.offset != 64 || tint.size != 16 || !tint.arrayDims.isEmpty())
        return fail("uniform member types/offsets/strides reflection required");
    std::puts("PASS_QT612_DESKTOP_SHADERTOOLS_QSB_REFLECTION_ONLY");
    return 0;
}
