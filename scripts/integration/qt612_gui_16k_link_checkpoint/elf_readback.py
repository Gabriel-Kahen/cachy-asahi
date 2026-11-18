# SPDX-License-Identifier: MIT
"""Check the actual QtGui link and its exact providers without loading any ELF."""

import hashlib
from pathlib import Path
import re
import struct


CHECKER = Path(__file__).resolve().parents[3] / "packages/port/qt612-gui-server-source-reference/check_stage.py"
CHECKER_PIN = dict(bytes=22362, sha256="35f410bf60af41f677f7a36d58cc5079ecf57dfde2b84f29dc1b006a4bf7f0da")
MD4C_PATH = "/usr/lib/libmd4c.so.0.5.3"
MD4C_PIN = dict(bytes=133128, sha256="d7754699fec7db8e53a7813547b4c1c0cfdde079ae09128401c379ec034bdef2")
SONAMES = {"gui": "libQt6Gui.so.6", "core": "libQt6Core.so.6",
           "dbus": "libQt6DBus.so.6", "md4c": "libmd4c.so.0"}
MAX_DSO = 128 << 20
PHDR = struct.Struct("<II6Q")
SHDR = struct.Struct("<II4QII2Q")
DYN = struct.Struct("<qQ")
SYMBOL = struct.Struct("<IBBHQQ")
RELA = struct.Struct("<QQq")
CALL_RELOCS = {1025: "R_AARCH64_GLOB_DAT", 1026: "R_AARCH64_JUMP_SLOT"}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def elf_checker():
    with CHECKER.open("rb") as stream:
        source = stream.read(CHECKER_PIN["bytes"] + 1)
    need(pin(source) == CHECKER_PIN, "Exact Qt family ELF checker required")
    namespace = {"__name__": "qtgui_pinned_family_elf_checker", "__file__": str(CHECKER)}
    exec(compile(source, str(CHECKER), "exec"), namespace)
    return namespace["elf_info"]


def inspect_dso(role, body, checker):
    info = checker(body)
    need(info["type"] == 3 and info["interpreter"] is None and info["soname"] == SONAMES[role]
         and info["machine"] == 183 and info["geometry_16k"] is True,
         f"Exact AArch64 {role} shared ELF, SONAME and 16 KiB load geometry required")
    start = struct.unpack_from("<Q", body, 32)[0]
    count = struct.unpack_from("<H", body, 56)[0]
    segments = [PHDR.unpack_from(body, start + i * PHDR.size) for i in range(count)]
    need(any(kind == 1 and flags & 1 and file_size > 0
             for kind, flags, _, _, _, file_size, _, _ in segments),
         f"Expected executable {role} load segment")
    need(len(info["needed"]) == len(set(info["needed"])), f"Duplicate {role} DT_NEEDED entry")
    return info, segments


def address_offset(loads, address, size):
    matches = [offset + address - virtual for _, _, offset, virtual, _, extent, _, _ in loads
               if size > 0 and virtual <= address and address + size <= virtual + extent]
    need(len(matches) == 1, "ELF dynamic address outside one file-backed load segment")
    return matches[0]


def dynamic_tags(body, segments):
    (_, _, offset, _, _, size, _, _), = [segment for segment in segments if segment[0] == 2]
    selected = {2, 5, 6, 7, 8, 9, 10, 11, 20, 23, 0x6ffffff0}
    tags = {}
    for tag, value in DYN.iter_unpack(memoryview(body)[offset:offset + size]):
        if tag == 0:
            break
        if tag in selected:
            need(tag not in tags, "Duplicate relevant ELF dynamic tag")
            tags[tag] = value
    need({5, 6, 10, 11} <= tags.keys() and tags[11] == SYMBOL.size, "Exact dynamic symbol table tags required")
    return tags


def md_parse_symbol(body, loads, tags):
    start = struct.unpack_from("<Q", body, 40)[0]
    entry_bytes, count = struct.unpack_from("<HH", body, 58)
    need(entry_bytes == SHDR.size and 1 <= count <= 4096 and start >= 64
         and start + entry_bytes * count <= len(body), "Bounded ELF section headers required")
    sections = [SHDR.unpack_from(body, start + i * entry_bytes) for i in range(count)]
    symbols = [row for row in sections if row[1] == 11]
    need(len(symbols) == 1, "One ELF dynamic symbol section required")
    _, _, _, address, offset, size, str_index, _, _, entry = symbols[0]
    need(entry == SYMBOL.size and size % entry == 0 and 0 < size // entry <= 1 << 20
         and 0 < str_index < count and address == tags[6] and address_offset(loads, address, size) == offset,
         "ELF section and dynamic symbol table must coincide")
    _, kind, _, str_address, str_offset, str_size, *_ = sections[str_index]
    need(kind == 3 and (str_address, str_size) == (tags[5], tags[10])
         and address_offset(loads, str_address, str_size) == str_offset
         and (offset + size <= str_offset or str_offset + str_size <= offset),
         "ELF section and dynamic string table must coincide without overlap")
    need(body[offset:offset + entry] == bytes(entry), "ELF dynamic symbol zero entry differs")
    matches = []
    for index, (name, info, visibility, section, value, length) in enumerate(
            SYMBOL.iter_unpack(memoryview(body)[offset:offset + size])):
        need(name < str_size, "ELF dynamic symbol name outside string table")
        name_at = str_offset + name
        if name_at + 9 <= str_offset + str_size and body[name_at:name_at + 9] == b"md_parse\0":
            matches.append((index, info, visibility, section, value, length))
    need(len(matches) == 1, "One exact dynamic md_parse symbol required")
    symbol = matches[0]
    if 0x6ffffff0 in tags:
        version = address_offset(loads, tags[0x6ffffff0] + symbol[0] * 2, 2)
        need(struct.unpack_from("<H", body, version)[0] == 1, "md_parse must be unversioned")
    return symbol


def md_parse_relocations(body, loads, tags, symbol_index):
    matches = {}
    for required, is_plt in (((7, 8, 9), False), ((23, 2, 20), True)):
        if not any(tag in tags for tag in required):
            continue
        need(all(tag in tags for tag in required), "Incomplete ELF dynamic relocation tags")
        address, size, encoding = (tags[tag] for tag in required)
        need(encoding == (7 if is_plt else RELA.size) and size % RELA.size == 0
             and 0 <= size // RELA.size <= 1 << 20, "Expected bounded ELF64 RELA relocations")
        if size == 0:
            continue
        offset = address_offset(loads, address, size)
        for index, (target, info, addend) in enumerate(RELA.iter_unpack(memoryview(body)[offset:offset + size])):
            if info >> 32 != symbol_index:
                continue
            kind = info & 0xffffffff
            need(kind in CALL_RELOCS and addend == 0 and target % 8 == 0
                 and sum(bool(flags & 2 and virtual <= target and target + 8 <= virtual + extent)
                         for _, flags, _, virtual, _, _, extent, _ in loads) == 1,
                 "md_parse requires a zero-addend call relocation into a writable load")
            matches[offset + index * RELA.size] = dict(type=CALL_RELOCS[kind], address=target)
    need(matches, "QtGui must contain a real runtime relocation to undefined md_parse")
    return list(matches.values())


def verify_link(gui, core, dbus, md4c, *, accepted_core):
    """Verify already captured ELF bodies against the independently accepted Core pin."""
    bodies = {"gui": gui, "core": core, "dbus": dbus, "md4c": md4c}
    need(all(type(body) is bytes and 64 <= len(body) <= MAX_DSO for body in bodies.values()),
         "Bounded original ELF bodies required")
    need(type(accepted_core) is dict and set(accepted_core) == {"bytes", "sha256"}
         and type(accepted_core["bytes"]) is int and type(accepted_core["sha256"]) is str
         and re.fullmatch("[0-9a-f]{64}", accepted_core["sha256"]), "External accepted QtCore pin required")
    pins = {role: pin(body) for role, body in bodies.items()}
    need(pins["core"] == accepted_core, "QtCore bytes differ from the accepted link")
    need(pins["md4c"] == MD4C_PIN, "System md4c bytes differ from the pinned Q3 provider")
    checker = elf_checker()
    inspected = {role: inspect_dso(role, body, checker) for role, body in bodies.items()}
    need({SONAMES[role] for role in ("core", "dbus", "md4c")} <= set(inspected["gui"][0]["needed"]),
         "QtGui must directly need the accepted QtCore, QtDBus and system md4c SONAMEs")
    need(SONAMES["core"] in inspected["dbus"][0]["needed"], "QtDBus must directly need the accepted QtCore SONAME")

    for role in ("gui", "md4c"):
        body = bodies[role]
        _, segments = inspected[role]
        loads = [item for item in segments if item[0] == 1]
        tags = dynamic_tags(body, segments)
        index, info, visibility, section, address, size = md_parse_symbol(body, loads, tags)
        if role == "gui":
            need(info in (0x10, 0x12) and visibility == 0 and section == address == size == 0,
                 "QtGui must import an undefined global md_parse")
            relocations = md_parse_relocations(body, loads, tags, index)
        else:
            need(info == 0x12 and visibility in (0, 3) and 0 < section < 0xff00 and size > 0
                 and sum(bool(flags & 1 and virtual <= address and address + size <= virtual + limit)
                         for _, flags, _, virtual, _, limit, _, _ in loads) == 1,
                 "Pinned system md4c must export a defined executable md_parse")
    return dict(architecture="aarch64", geometry_16k=True, provider_path=MD4C_PATH,
                libraries={role: dict(pin=pins[role], soname=info["soname"], needed=info["needed"],
                                      load_segments=info["load_segments"])
                           for role, (info, _) in inspected.items()},
                md_parse=dict(imported=True, relocation=relocations, provider_export=True))
