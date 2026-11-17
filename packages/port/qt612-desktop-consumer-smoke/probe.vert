// SPDX-License-Identifier: MIT
#version 440

layout(location = 0) in vec3 position;
layout(location = 1) in vec4 color;
layout(location = 0) out vec4 vertexColor;

layout(std140, binding = 0) uniform Params {
    mat4 transform;
    vec4 tint;
} params;

void main()
{
    gl_Position = params.transform * vec4(position, 1.0);
    vertexColor = color * params.tint;
}
