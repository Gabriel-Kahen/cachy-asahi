# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Original deterministic P4 fixtures and bounded semantic comparison; no actors."""
import argparse
import json
from pathlib import Path


def need(value, message):
    if not value:
        raise ValueError(message)


def fixtures():
    patterns = [(1, 1, 0), (1, 1, 1), (13, 7, 2), (32, 9, 3), (17, 11, 4)]
    output = {}
    for number, (width, height, pattern) in enumerate(patterns):
        raster = bytearray(((width + 7) // 8) * height)
        for y in range(height):
            for x in range(width):
                bit = (0, 1, (x + y) % 2, y % 2, (x * 3 + y * 5) % 7 < 3)[pattern]
                if bit:
                    raster[y * ((width + 7) // 8) + x // 8] |= 128 >> (x % 8)
        output[f"synthetic-{number}.pbm"] = f"P4\n{width} {height}\n".encode() + raster
    return output


def decode(body):
    need(len(body) <= 1048576, "PBM byte cap")
    cursor = 0
    tokens = []
    for _ in range(3):
        while cursor < len(body):
            if body[cursor] in b" \t\r\n\v\f":
                cursor += 1
            elif body[cursor] == 35:
                end = body.find(b"\n", cursor)
                need(end >= 0, "unterminated comment")
                cursor = end + 1
            else:
                break
        start = cursor
        while cursor < len(body) and body[cursor] not in b" \t\r\n\v\f#":
            cursor += 1
        need(0 < cursor - start <= 8, "header token cap")
        tokens.append(body[start:cursor])
    need(tokens[0] == b"P4", "P4 required")
    need(all(token.isdigit() for token in tokens[1:]), "decimal dimensions")
    width, height = map(int, tokens[1:])
    need(1 <= width <= 1024 and 1 <= height <= 512, "dimension cap")
    need(cursor < len(body) and body[cursor] in b" \t\r\n\v\f", "raster delimiter")
    stride = (width + 7) // 8
    expected = stride * height
    # Consume only the delimiter, never whitespace-valued raster bytes. Accept
    # a CRLF delimiter only when the bounded exact raster length proves it.
    if body[cursor:cursor + 2] == b"\r\n" and len(body) - cursor == expected + 2:
        cursor += 2
    else:
        cursor += 1
    raster = body[cursor:]
    need(len(raster) == expected, "exact raster size")
    # PBM bits beyond width are row padding; compare only the defined pixels.
    pixels = tuple((raster[y * stride + x // 8] >> (7 - x % 8)) & 1
                   for y in range(height) for x in range(width))
    return width, height, pixels


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=Path)
    parser.add_argument("--compare", nargs=2, type=Path)
    args = parser.parse_args()
    need(bool(args.write) != bool(args.compare), "select write or compare")
    if args.write:
        args.write.mkdir(mode=0o700)
        for name, body in fixtures().items():
            with (args.write / name).open("xb") as stream:
                stream.write(body)
        print(json.dumps({"original_synthetic_fixtures": 5, "external_images_used": False}))
    else:
        need(all(path.stat().st_size <= 1048576 for path in args.compare), "PBM byte cap")
        need(decode(args.compare[0].read_bytes()) == decode(args.compare[1].read_bytes()), "roundtrip mismatch")
        print(json.dumps({"decoded_dimensions_and_pixels_equal": True}))
