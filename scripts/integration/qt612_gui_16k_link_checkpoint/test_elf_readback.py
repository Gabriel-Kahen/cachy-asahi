# SPDX-License-Identifier: MIT
"""Passive synthetic ELF controls for the QtGui linkage reader."""

import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch


def load_reader():
    path = Path(__file__).with_name("elf_readback.py")
    spec = importlib.util.spec_from_file_location("qtgui_test_reader", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E = load_reader()
REQUIRED = [E.SONAMES[role] for role in ("core", "dbus", "md4c")]


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "ctypes.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("A passive ELF test attempted to launch or load an actor: " + event)


sys.addaudithook(fence)


def fixture(role, needed=(), *, symbol_section=0, symbol_info=0x12, reloc=1026, addend=0,
            target=0x14600, alignment=16384, elf_type=3, version=1):
    body = bytearray(0xc00)
    body[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", body, 16, elf_type, 183, 1, 0, 64, 0x800, 0,
                     64, E.PHDR.size, 3, E.SHDR.size, 4, 0)
    strings = bytearray(1)
    offsets = {}
    for name in (E.SONAMES[role], *needed, "md_parse"):
        offsets[name] = len(strings)
        strings.extend(name.encode() + b"\0")
    tags = [(14, offsets[E.SONAMES[role]]), (5, 0x10280), (6, 0x10200), (10, len(strings)),
            (11, E.SYMBOL.size), (0x6ffffff0, 0x10300)]
    tags.extend((1, offsets[name]) for name in needed)
    if reloc is not None:
        tags.extend([(23, 0x10330), (2, E.RELA.size), (20, 7)])
        E.RELA.pack_into(body, 0x330, target, (1 << 32) | reloc, addend)
    tags.append((0, 0))
    segments = [(1, 5, 0, 0x10000, 0, 0x400, 0x400, alignment),
                (1, 6, 0x400, 0x14400, 0, 0x400, 0x400, alignment),
                (2, 6, 0x440, 0x14440, 0, len(tags) * E.DYN.size, len(tags) * E.DYN.size, 8)]
    for number, segment in enumerate(segments):
        E.PHDR.pack_into(body, 64 + number * E.PHDR.size, *segment)
    for number, tag in enumerate(tags):
        E.DYN.pack_into(body, 0x440 + number * E.DYN.size, *tag)
    E.SYMBOL.pack_into(body, 0x200 + E.SYMBOL.size, offsets["md_parse"], symbol_info, 0, symbol_section,
                       0x10360 if symbol_section else 0, 4 if symbol_section else 0)
    struct.pack_into("<HH", body, 0x300, 0, version)
    body[0x280:0x280 + len(strings)] = strings
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (0, 11, 2, 0x10200, 0x200, 2 * E.SYMBOL.size, 2, 1, 8, E.SYMBOL.size),
                (0, 3, 2, 0x10280, 0x280, len(strings), 0, 0, 1, 0),
                (0, 1, 6, 0x10360, 0x360, 4, 0, 0, 4, 0)]
    for number, section in enumerate(sections):
        E.SHDR.pack_into(body, 0x800 + number * E.SHDR.size, *section)
    return bytes(body)


class ElfTests(unittest.TestCase):
    def setUp(self):
        self.gui = fixture("gui", REQUIRED)
        self.core = fixture("core", reloc=None)
        self.dbus = fixture("dbus", [E.SONAMES["core"]], reloc=None)
        self.md4c = fixture("md4c", symbol_section=3, reloc=None)
        self.accepted_core = E.pin(self.core)
        model_pin = patch.object(E, "MD4C_PIN", E.pin(self.md4c))
        model_pin.start()
        self.addCleanup(model_pin.stop)

    def verify(self):
        return E.verify_link(self.gui, self.core, self.dbus, self.md4c, accepted_core=self.accepted_core)

    def test_linked_gui_needs_exact_providers_and_relocates_md_parse(self):
        actual = self.verify()
        self.assertEqual(actual["libraries"]["core"]["pin"], self.accepted_core)
        self.assertEqual(actual["libraries"]["md4c"]["soname"], "libmd4c.so.0")
        self.assertEqual(actual["md_parse"], dict(imported=True, provider_export=True,
                                                  relocation=[dict(type="R_AARCH64_JUMP_SLOT", address=0x14600)]))

    def test_qtgui_requires_all_three_dynamic_dependency_edges(self):
        for omitted in REQUIRED:
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, "directly need"):
                self.gui = fixture("gui", [name for name in REQUIRED if name != omitted])
                self.verify()
        self.gui = fixture("gui", REQUIRED)
        self.dbus = fixture("dbus")
        with self.assertRaisesRegex(ValueError, "QtDBus must directly need"):
            self.verify()

    def test_required_symbol_is_a_real_dynamic_import_and_relocation(self):
        for kwargs, error in ((dict(reloc=None), "real runtime relocation"),
                              (dict(reloc=257), "zero-addend call relocation"),
                              (dict(addend=4), "zero-addend call relocation"),
                              (dict(target=0x10360), "writable load"),
                              (dict(symbol_section=3), "undefined global"),
                              (dict(version=2), "must be unversioned")):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, error):
                self.gui = fixture("gui", REQUIRED, **kwargs)
                self.verify()

    def test_section_symbols_must_be_the_runtime_symbols(self):
        changed = bytearray(self.gui)
        struct.pack_into("<Q", changed, 0x800 + E.SHDR.size + 16, 0x10218)
        self.gui = bytes(changed)
        with self.assertRaisesRegex(ValueError, "section and dynamic symbol table"):
            self.verify()

    def test_core_and_md4c_pin_refuse_body_replacement(self):
        original = self.core
        self.core += b"suffix"
        with self.assertRaisesRegex(ValueError, "differ from the accepted link"):
            self.verify()
        self.core = original
        self.md4c += b"suffix"
        with self.assertRaisesRegex(ValueError, "differ from the pinned Q3 provider"):
            self.verify()

    def test_md4c_must_define_the_callable_export(self):
        self.md4c = fixture("md4c")
        with patch.object(E, "MD4C_PIN", E.pin(self.md4c)), self.assertRaisesRegex(ValueError, "defined executable"):
            self.verify()

    def test_gui_geometry_soname_and_shared_type(self):
        for gui, error in ((fixture("gui", REQUIRED, alignment=4096), "16K load geometry"),
                           (fixture("core"), "shared ELF, SONAME"),
                           (fixture("gui", REQUIRED, elf_type=2), "shared ELF, SONAME")):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                self.gui = gui
                self.verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
