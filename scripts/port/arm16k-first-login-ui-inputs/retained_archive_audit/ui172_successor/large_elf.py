"""Bounded static ELF adapter. Stream into ELFBuffer; never execute an ELF.

The version parser slices DT_STRTAB and its suffixes. These slices must remain
views: copying them repeatedly is unsafe for the retained large LLVM/Mesa DSOs.
Only decoded names/interpreters (at most 4096 bytes) become separate bytes.
"""
import functools
import hashlib
import importlib.util
import operator
from pathlib import Path
import resource
import time

MIB = 1024 ** 2
MAX_OBJECT_BYTES = 192 * MIB
PROCESS_LIMIT_BYTES = 768 * MIB
MAX_STRING_BYTES = 4096
MAX_OPERATIONS = 500000
MAX_PARSE_SECONDS = 120
ROOT = Path(__file__).resolve().parents[5]
SOURCES = {
    'elf': ('scripts/platform/elf_audit.py',
            '72ec18c7d8580094164b3ea4c11fcff2583519b4cd861e5c436ec9d7a779401b'),
    'geometry': ('scripts/checks/package_checks.py',
                 '314e8b4a0920b3f6d93619fc74ad1d63a6210d1b17b925618451b493d2610a1a'),
    'versions': ('scripts/port/arm-rust-toolchain-inputs/qtbase-successor/elf_versions.py',
                 '6cf4a17b22dd6df28ace686ca1b3f4d6f5ed9248910a0f7f787ad65046e73285'),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def limit_process():
    """Dedicated worker limit; never loosen a caller's existing restriction."""
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    hard = PROCESS_LIMIT_BYTES if hard == resource.RLIM_INFINITY else min(hard, PROCESS_LIMIT_BYTES)
    soft = hard if soft == resource.RLIM_INFINITY else min(soft, hard)
    resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
    return soft


class _View:
    """A slice referencing a real bytearray buffer, with noncopying searches."""
    __slots__ = ('owner', 'start', 'stop')

    def __init__(self, owner, start, stop):
        self.owner, self.start, self.stop = owner, start, stop

    def __len__(self):
        return self.stop - self.start

    def __getitem__(self, key):
        self.owner._step()
        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            require(step == 1, 'strided ELF view refused')
            return _View(self.owner, self.start + start, self.start + max(start, stop))
        index = operator.index(key)
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError('ELF view index')
        return bytearray.__getitem__(self.owner, self.start + index)

    def __eq__(self, other):
        if isinstance(other, _View):
            other = memoryview(other.owner)[other.start:other.stop]
        if not isinstance(other, (bytes, bytearray, memoryview)):
            return NotImplemented
        return memoryview(self.owner)[self.start:self.stop] == other

    def __bytes__(self):
        self.owner._step()
        require(len(self) <= MAX_STRING_BYTES, 'ELF string copy bound')
        return bytes(memoryview(self.owner)[self.start:self.stop])

    def decode(self, encoding='utf-8', errors='strict'):
        return bytes(self).decode(encoding, errors)

    def find(self, value, start=0, stop=None):
        stop = len(self) if stop is None else stop
        require(0 <= start <= stop <= len(self), 'ELF view search range')
        found = self.owner.find(value, self.start + start, self.start + stop)
        return -1 if found < 0 else found - self.start

    def index(self, value, start=0, stop=None):
        found = self.find(value, start, stop)
        if found < 0:
            raise ValueError('ELF view substring not found')
        return found

    def __contains__(self, value):
        if isinstance(value, int):
            value = bytes([value])
        return self.find(value) >= 0


class ELFBuffer(bytearray):
    """One real C buffer; bounded streaming extend, view-producing slices.

    Constructor accepts a size or a small stream prefix. Do not construct from
    an already allocated large bytes object: that would duplicate the object.
    """
    def __init__(self, initial=0):
        limit_process()
        if type(initial) is int:
            require(0 <= initial <= MAX_OBJECT_BYTES, 'ELF object byte cap')
        else:
            require(isinstance(initial, (bytes, bytearray, memoryview)) and
                    len(initial) <= MIB, 'large ELF must stream into ELFBuffer')
        self._budget = None
        super().__init__(initial)

    def _step(self):
        if self._budget is not None:
            self._budget[0] -= 1
            require(self._budget[0] >= 0 and time.monotonic() <= self._budget[1],
                    'ELF inspection operation/time bound')

    def __getitem__(self, key):
        if isinstance(key, slice):
            self._step()
            start, stop, step = key.indices(len(self))
            require(step == 1, 'strided ELF buffer refused')
            return _View(self, start, max(start, stop))
        return super().__getitem__(key)

    def extend(self, block):
        require(isinstance(block, (bytes, bytearray, memoryview)) and
                len(self) + len(block) <= MAX_OBJECT_BYTES, 'ELF object byte cap')
        return super().extend(block)

    def __iadd__(self, block):
        self.extend(block)
        return self

    def find(self, value, start=0, stop=None):
        self._step()
        return super().find(value, start, len(self) if stop is None else stop)


def _check_modules(modules):
    for name, (_, expected) in SOURCES.items():
        path = Path(modules[name].__file__)
        require(path.stat().st_size <= MIB and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                'ELF parser source pin: ' + name)
    return modules


@functools.cache
def _modules():
    loaded = {}
    for name, (relative, expected) in SOURCES.items():
        path = ROOT / relative
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                'ELF parser source pin: ' + name)
        spec = importlib.util.spec_from_file_location('ui172_large_' + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        loaded[name] = module
    return loaded


def inspect(data, modules=None, object_cap=MAX_OBJECT_BYTES):
    """Return the three original parsers' observations; no runtime acceptance.

    The caller owns the encompassing archive/600-second budget. This function
    additionally caps parser searches to 120 seconds/500000 operations and
    the worker to 768 MiB. Large objects must already be ELFBuffer instances.
    """
    limit_process()
    require(type(object_cap) is int and 0 < object_cap <= MAX_OBJECT_BYTES,
            'ELF object cap policy')
    require(0 < len(data) <= object_cap, 'ELF object byte cap')
    if not isinstance(data, ELFBuffer):
        require(isinstance(data, (bytes, bytearray)) and len(data) <= MIB,
                'large ELF must stream into ELFBuffer')
        data = ELFBuffer(data)
    modules = _check_modules(_modules() if modules is None else modules)
    require(data.startswith(b'\x7fELF'), 'ELF magic required')
    data._budget = [MAX_OPERATIONS, time.monotonic() + MAX_PARSE_SECONDS]
    try:
        parsed = modules['elf'].parse_elf(data)
        geometry = modules['geometry'].elf_check(data)
        target = parsed['class'] == 64 and parsed['byte_order'] == 'little' and parsed['machine'] == 183
        versions = modules['versions'].parse(data) if target else {'needs': {}, 'defines': []}
        classification = ('AARCH64_STRUCTURAL_16K_OBSERVED' if target and
                          parsed['classification'] == 'aarch64-loadable-elf' and not geometry['errors']
                          else 'AARCH64_STRUCTURAL_16K_REFUSED' if target and parsed['type'] in (2, 3)
                          else 'RELOCATABLE_DATA_NO_RUNTIME_PROOF' if target and parsed['type'] == 1
                          else 'WRONG_ARCHITECTURE_OR_RUNTIME_SCOPE_UNRESOLVED')
        return {'elf': parsed, 'geometry': geometry, 'gnu_versions': versions,
                'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'classification': classification, 'runtime_load_verified': False,
                'process_limit_bytes': resource.getrlimit(resource.RLIMIT_AS)[0],
                'object_cap_bytes': object_cap}
    except MemoryError:
        raise ValueError('ELF inspection memory bound') from None
    finally:
        data._budget = None


inspect_buffer = inspect
