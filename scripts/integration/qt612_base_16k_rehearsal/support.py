# SPDX-License-Identifier: MIT
"""Shared finite data and checked copy from the existing QEMU controller."""

import importlib.util
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


O = load(REPO / "scripts/install/overlay583_trial/controller.py", "qtbase_held_qemu")
T = O.T


def pair(row):
    size, digest = row["bytes"], row["sha256"]
    T.need(type(size) is int and 0 <= size <= 2 << 30 and
           type(digest) is str and re.fullmatch("[0-9a-f]{64}", digest), "Exact bounded pin")
    return dict(bytes=size, sha256=digest)


def checked(path, pin, *, collect=True):
    if isinstance(pin, tuple):
        pin = dict(bytes=pin[0], sha256=pin[1])
    return T.read(path, pin, cap=pin["bytes"], collect=collect)


def entry(path, pin=None):
    if pin is None:
        pin = T.read(path, cap=128 << 10, collect=False)
    return dict(path=str(path), **pin)


def put_text(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(value)
    path.chmod(0o444)


def put_json(path, value):
    put_text(path, T.encoded(value).decode())
