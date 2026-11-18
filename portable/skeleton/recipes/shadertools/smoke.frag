#version 440
// SPDX-License-Identifier: MIT
layout(location = 0) in vec4 vColor;
layout(location = 0) out vec4 fragColor;
layout(binding = 1) uniform sampler2D uTexture;
layout(std140, binding = 0) uniform buf { float opacity; } ubuf;
void main() { fragColor = texture(uTexture, vec2(0.5)) * vColor * ubuf.opacity; }
