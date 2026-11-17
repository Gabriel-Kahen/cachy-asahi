#version 440
// SPDX-License-Identifier: MIT
layout(location = 0) in vec4 iPosition;
layout(location = 0) out vec4 vColor;
layout(std140, binding = 0) uniform buf { mat4 mvp; } ubuf;
void main() { vColor = vec4(0.25, 0.5, 0.75, 1.0); gl_Position = ubuf.mvp * iPosition; }
