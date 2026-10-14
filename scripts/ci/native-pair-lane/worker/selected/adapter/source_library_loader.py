# SPDX-License-Identifier: MIT
"""Closed held-Source/library adapters. Default admission anchor is unbound.

Root injects only the exact freshly admitted capability class through its held
bootstrap. This is trusted Source loading, not a Python sandbox. Controls replace
all compilation/execution/loading backends; actual actors require another grant.
"""
import builtins
import hashlib
import json
from types import ModuleType, MappingProxyType

ROOT_ADMISSION_TYPE = None
ROOT_SOURCE_ROWS = None
ROOT_SOURCE_BINDING = None
SOURCE_BINDING = '8fbbcb8f5a4365e4f1a46dda6e05d03eb31b3edd76ea0dbf7f28a55633424612'
SOURCE_ROWS = {'artifact_custody.py': {'bytes': 19108,
                         'mode': 420,
                         'sha256': '3b326dc823590f18e1f07a494da0a9ad8e262fe66f48a63f0fd6ad3c2affe67c'},
 'authority.py': {'bytes': 3565,
                  'mode': 420,
                  'sha256': '139d1236ed823a9fd344f6e2485121c53aeadfe79d78cd0fb03ed45b609ac80b'},
 'checker.py': {'bytes': 8202,
                'mode': 420,
                'sha256': '8db8314b8720d0dbe34280ee29faec0e38b24b562d774c30710e31a8339d7928'},
 'pair_archive.py': {'bytes': 13669,
                     'mode': 420,
                     'sha256': 'b5fd255a8779fccc0b598cabf01743ddc597d2b314703ae1f77f38fcb3c801fe'},
 'pair_compare.py': {'bytes': 12801,
                     'mode': 420,
                     'sha256': '54acd6085d9fb84e5955a6970994a24788fda513ff1de78c3a4baa581eda817f'},
 'zstd_owner.py': {'bytes': 8091,
                   'mode': 420,
                   'sha256': '229063e774c9306c3fa9d61b71c8bc075f39b7772054c9287743cf71400e55e6'}}
ORDER = ('authority.py', 'artifact_custody.py', 'zstd_owner.py',
         'pair_archive.py', 'pair_compare.py', 'checker.py')
GRAPH = {
    'authority': {'math'},
    'artifact_custody': {'hashlib', 're', 'dataclasses'},
    'zstd_owner': {'ctypes', 'hashlib'},
    'pair_archive': {'hashlib', 'json', 're'},
    'pair_compare': {'hashlib', 'json', 're'},
    'checker': {'hashlib', 're', 'artifact_custody', 'pair_archive', 'pair_compare', 'zstd_owner'},
}
STDLIB = {'math', 'hashlib', 're', 'dataclasses', 'ctypes', 'json'}
SOURCE_TOTAL = 4 * 1024 * 1024
CHUNK = 65536
ABI = {
    'pointer_bits': 64, 'size_t_bits': 64,
    'signatures': {
        'ZSTD_createDStream': ((), 'ptr'),
        'ZSTD_initDStream': (('ptr',), 'size_t'),
        'ZSTD_DCtx_setParameter': (('ptr', 'int', 'int'), 'size_t'),
        'ZSTD_decompressStream': (('ptr', 'out*', 'in*'), 'size_t'),
        'ZSTD_freeDStream': (('ptr',), 'size_t'),
        'ZSTD_isError': (('size_t',), 'uint'),
    },
}
LIBRARY_REFERENCE = {'path': 'usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5',
                     'canonical_path': '/usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5',
                     'bytes': 657432, 'mode': 0o644,
                     'sha256': 'fe726238b170b83aa83bf1f8a79109b8b61b9eb45234304511d093bbe5f5fb20',
                     'uid': 0, 'gid': 0}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def record(authority, error, cleanup=False):
    try:
        authority.record_failure(error, cleanup=cleanup)
    except BaseException:
        pass


def authenticate(admission, authority, kind):
    need(ROOT_ADMISSION_TYPE is not None and type(admission) is ROOT_ADMISSION_TYPE,
         'loader-typed-root-capability-pending')
    need(admission.authority is authority and admission.enabled is True,
         'loader-original-authority-binding')
    authority.check(cleanup=kind == 'cleanup')
    need(admission.authenticate(kind, authority) is True, 'loader-capability-identity')
    need(admission.check(kind) is True, 'loader-current-job-admission')
    authority.check(cleanup=kind == 'cleanup')


def uncertain(authority, admission, kind, key):
    try:
        admission.uncertain(kind, key)
    except BaseException as error:
        record(authority, error)


def action(authority, admission, kind, callback, *args):
    authenticate(admission, authority, kind)
    result = callback(*args)
    authenticate(admission, authority, kind)
    return result


def _rows(value):
    # Retained0245 constants are references. Only Root's separately held
    # bootstrap may inject an immutable corrected Source selection.
    need(type(ROOT_SOURCE_ROWS) is MappingProxyType and type(ROOT_SOURCE_BINDING) is str,
         'loader-root-source-selection-pending')
    need(type(value) in (dict, MappingProxyType) and set(value) == set(ORDER)
         and set(ROOT_SOURCE_ROWS) == set(ORDER), 'loader-six-source-membership')
    rows = {name: dict(value[name]) for name in ORDER}
    selected = {name: dict(ROOT_SOURCE_ROWS[name]) for name in ORDER}
    need(rows == selected and all(set(r) == {'bytes','mode','sha256'} and
         type(r['bytes']) is int and 0 < r['bytes'] <= SOURCE_TOTAL and
         type(r['mode']) is int and r['mode'] == 0o644 and
         type(r['sha256']) is str and len(r['sha256']) == 64 and
         all(c in '0123456789abcdef' for c in r['sha256']) for r in rows.values()) and
         sum(r['bytes'] for r in rows.values()) <= SOURCE_TOTAL, 'loader-fixed-source-rows')
    body = json.dumps(rows, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    need(hashlib.sha256(body).hexdigest() == ROOT_SOURCE_BINDING, 'loader-source-binding')
    return rows


def verify_holder(item, role, authority, admission):
    kind = 'source' if role == 'source' else 'library'
    verifier = action(authority, admission, kind, getattr, admission, 'verify_holder')
    proof = action(authority, admission, kind, verifier, item, role)
    need(proof is True, 'loader-positive-original-holder-binding')


def verify_held(item, role, authority, admission):
    kind = 'source' if role == 'source' else 'library'
    verify_holder(item, role, authority, admission)
    verify = action(authority, admission, kind, getattr, item, 'verify')
    result = action(authority, admission, kind, verify)
    need(result is True, 'loader-positive-held-verification')
    verify_holder(item, role, authority, admission)


def held_action(item, role, authority, admission, method, *args):
    # Establish trusted type/original holder before even resolving a descriptor
    # method or attribute. Recheck after the operation before releasing its value.
    kind = 'source' if role == 'source' else 'library'
    verify_held(item, role, authority, admission)
    callback = action(authority, admission, kind, getattr, item, method)
    value = action(authority, admission, kind, callback, *args)
    verify_held(item, role, authority, admission)
    return value


def held_attribute(item, role, authority, admission, name):
    kind = 'source' if role == 'source' else 'library'
    verify_held(item, role, authority, admission)
    value = action(authority, admission, kind, getattr, item, name)
    verify_held(item, role, authority, admission)
    return value


def _read(item, row, authority, admission, kind):
    verify_held(item, 'source', authority, admission)
    actual = {key: held_attribute(item, 'source', authority, admission, attribute)
              for key, attribute in [('bytes','size'),('sha256','sha256'),('mode','mode')]}
    need(actual == row, 'loader-held-source-pin')
    held_action(item, 'source', authority, admission, 'rewind')
    data = bytearray()
    for _ in range(128):
        if len(data) == row['bytes']:
            break
        maximum = min(CHUNK, row['bytes'] - len(data))
        chunk = held_action(item, 'source', authority, admission, 'read', maximum)
        need(type(chunk) is bytes and 0 < len(chunk) <= maximum, 'loader-source-read')
        data.extend(chunk)
    need(len(data) == row['bytes'] and held_action(item, 'source', authority, admission, 'read', 1) == b'', 'loader-source-bound')
    need(hashlib.sha256(data).hexdigest() == row['sha256'], 'loader-source-body-pin')
    verify_held(item, 'source', authority, admission)
    return bytes(data)


class SourceModuleMapping:
    """Private retained module objects, including failed partial initialization."""
    def __init__(self):
        self.modules, self.executed, self.uncertainties = {}, set(), []
        self.complete = False


class SourceCompiler:
    """Concrete adapter. Never reached without a typed current-job Root grant."""
    def allocate(self, name, adopt):
        module = ModuleType(name)
        adopt(module)
        return module
    def compile(self, raw, name):
        return builtins.compile(raw, '<held:' + name + '>', 'exec', dont_inherit=True, optimize=0)
    def execute(self, code, module, importer, stdlib):
        namespace = dict(builtins.__dict__)
        namespace['__import__'] = importer
        module.__dict__['__builtins__'] = namespace
        builtins.exec(code, module.__dict__, module.__dict__)


def load_sources(source_artifacts6, expected_rows6, authority, admission, *, compiler=None):
    """Compile/execute exact held6 Source with only its closed import graph.

    Every complete closure reread charges the same original custody budget.
    Adopted modules are retained even when allocation/execution returns late or
    fails after effects. No module is published into ambient sys.modules/path.
    """
    mapping = SourceModuleMapping()
    mapping.authority, mapping.admission, mapping.source_artifacts = authority, admission, source_artifacts6
    try:
        authenticate(admission, authority, 'source')
        rows = _rows(expected_rows6)
        need(_rows(admission.source_rows) == rows and admission.source_binding == ROOT_SOURCE_BINDING, 'loader-root-source-selection')
        need(type(source_artifacts6) is dict and set(source_artifacts6) == set(ORDER), 'loader-held-source-membership')
        need(type(admission.stdlib) is MappingProxyType and set(admission.stdlib) == STDLIB
             and all(type(v) is ModuleType for v in admission.stdlib.values()), 'loader-closed-stdlib-selection')
        binding = ROOT_SOURCE_BINDING
        admission.retain('source-load', binding, mapping)
        authenticate(admission, authority, 'source')
        backend = SourceCompiler() if compiler is None else compiler

        def closure():
            authenticate(admission, authority, 'source')
            need(_rows(admission.source_rows) == rows and ROOT_SOURCE_BINDING == binding, 'loader-source-selection-drift')
            bodies = {name: _read(source_artifacts6[name], rows[name], authority, admission, 'source') for name in ORDER}
            need(sum(map(len, bodies.values())) <= SOURCE_TOTAL, 'loader-source-total')
            authenticate(admission, authority, 'source')
            return bodies

        closure()
        for name in ORDER:
            stem = name[:-3]
            private_name = '_pair_' + binding + '.' + stem
            adopted = []
            def adopt(module):
                need(not adopted and type(module) is ModuleType and module.__name__ == private_name, 'loader-module-adoption')
                mapping.modules[stem] = module
                adopted.append(module)
            try:
                module = backend.allocate(private_name, adopt)
                need(len(adopted) == 1 and module is adopted[0], 'loader-unadopted-module')
                authenticate(admission, authority, 'source')
            except BaseException as error:
                record(authority, error)
                if not adopted:
                    mapping.uncertainties.append(stem)
                    uncertain(authority, admission, 'source-module', private_name)
                raise
            bodies = closure()
            code = action(authority, admission, 'source', backend.compile, bodies[name], private_name)
            closure()
            def importer(request, globals=None, locals=None, fromlist=(), level=0, _stem=stem):
                authenticate(admission, authority, 'source')
                need(type(request) is str and level == 0 and request in GRAPH[_stem], 'loader-closed-import-graph')
                need(type(fromlist) in (tuple, list) and '*' not in fromlist, 'loader-import-fromlist')
                if request in STDLIB:
                    value = admission.stdlib[request]
                else:
                    need(request in mapping.executed, 'loader-uninitialized-helper-import')
                    value = mapping.modules[request]
                authenticate(admission, authority, 'source')
                return value
            action(authority, admission, 'source', backend.execute, code, module, importer, admission.stdlib)
            closure()
            mapping.executed.add(stem)
        closure()
        authenticate(admission, authority, 'source')
        mapping.complete = True
        return MappingProxyType(dict(mapping.modules))
    except BaseException as error:
        record(authority, error)
        raise


class CtypesBackend:
    """Concrete admitted mapper. C/linker calls are synchronous, not preempted.

    Constructor failure cannot establish an absent mapping. There is no dlclose
    fallback: library/dependency owners and unknown mappings remain retained.
    """
    def __init__(self, ctypes_module):
        self.ctypes = ctypes_module
    def map_fd(self, descriptor, adopt):
        mapping = self.ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=2)
        adopt(mapping)
        return mapping
    def declare(self, mapping, abi):
        c = self.ctypes
        need(c.sizeof(c.c_void_p) * 8 == c.sizeof(c.c_size_t) * 8 == 64, 'loader-abi-width')
        class Input(c.Structure):
            _fields_ = [('src', c.c_void_p), ('size', c.c_size_t), ('pos', c.c_size_t)]
        class Output(c.Structure):
            _fields_ = [('dst', c.c_void_p), ('size', c.c_size_t), ('pos', c.c_size_t)]
        types = {'ptr': c.c_void_p, 'size_t': c.c_size_t, 'int': c.c_int,
                 'uint': c.c_uint, 'out*': c.POINTER(Output), 'in*': c.POINTER(Input)}
        for name, (args, result) in abi['signatures'].items():
            function = getattr(mapping, name)
            need(callable(function), 'loader-abi-symbol')
            function.argtypes = [types[arg] for arg in args]
            function.restype = types[result]
        return mapping


class LibraryLoader:
    """Retained, current-job mapper for one exact admitted held ARM library.

    No retained reference row supplies a grant. Root's immutable typed capability
    authenticates interpreter/linker/ELF mapping assumptions and a positive fresh
    mapping inspector. The caller retains this object and all Artifact owners.
    """
    def __init__(self, library, dependencies, authority, admission, *, backend=None):
        self.library, self.dependencies = library, dependencies
        self.authority, self.admission = authority, admission
        self.backend = backend
        self.mappings, self.uncertainties = [], []
        self.failed = False
        self._API = None
        try:
            authenticate(admission, authority, 'library')
            admission.retain('library-loader', admission.job['nonce'], self)
            self._verify()
            if self.backend is None:
                self.backend = CtypesBackend(admission.stdlib['ctypes'])
            authenticate(admission, authority, 'library')
        except BaseException as error:
            self.failed = True
            record(authority, error)
            raise

    def _verify(self):
        authenticate(self.admission, self.authority, 'library')
        row = dict(self.admission.library_row)
        need(row == LIBRARY_REFERENCE, 'loader-library-reference-not-selection')
        need(dict(self.admission.ABI) == ABI, 'loader-fixed-abi')
        policy = self.admission.loader_policy
        need(set(policy) == {'mapping_policy', 'latency', 'exclusive_fd_owner'}
             and policy['mapping_policy'] == 'held-fd-exact-mapped-closure'
             and policy['latency'] == 'observe-late-refuse'
             and policy['exclusive_fd_owner'] is True, 'loader-linkage-policy')
        selected = self.admission.dependencies
        need(type(self.dependencies) is dict and type(selected) is MappingProxyType
             and set(self.dependencies) == set(selected) and 0 < len(selected) <= 32,
             'loader-dependency-membership')
        for name, item, pin in [(row['path'], self.library, row)] + [(n, self.dependencies[n], dict(selected[n])) for n in sorted(selected)]:
            need(type(name) is str and not name.startswith('/') and '..' not in name.split('/')
                 and len(name) <= 256 and all(name.split('/')), 'loader-canonical-held-path')
            need(set(pin) == ({'path','canonical_path','bytes','mode','sha256','uid','gid'} if item is self.library else {'bytes','mode','sha256','uid','gid'}), 'loader-row-shape')
            need(type(pin['bytes']) is int and 0 < pin['bytes'] <= 64 * 1024 * 1024
                 and type(pin['mode']) is int and pin['mode'] in (0o644,0o755)
                 and type(pin['uid']) is type(pin['gid']) is int and pin['uid'] == pin['gid'] == 0
                 and type(pin['sha256']) is str and len(pin['sha256']) == 64
                 and all(c in '0123456789abcdef' for c in pin['sha256']), 'loader-root-helper-row')
            role = 'library' if item is self.library else 'dependency'
            verify_held(item, role, self.authority, self.admission)
            actual = {key: held_attribute(item, role, self.authority, self.admission, attribute)
                      for key, attribute in [('path','path'),('bytes','size'),('mode','mode'),('sha256','sha256')]}
            need(actual == {'path': name, **{key: pin[key] for key in ('bytes','mode','sha256')}},
                 'loader-held-library-pin')
        inspector = self.admission.mapping_inspector
        need(type(inspector) is self.admission.mapping_inspector_type, 'loader-typed-mapping-inspector')
        authenticate(self.admission, self.authority, 'library')

    def __call__(self, held_fd):
        try:
            authenticate(self.admission, self.authority, 'library')
            need(not self.failed, 'loader-failed-or-uncertain')
            self._verify()
            descriptor = held_attribute(self.library, 'library', self.authority, self.admission, 'fd')
            need(type(descriptor) is int and descriptor >= 0 and type(held_fd) is int and held_fd == descriptor,
                 'loader-exact-held-fd')
            if self._API is not None:
                self._mapping_proof(self.mappings[0])
                self._verify()
                return self._API
            preflight = action(self.authority, self.admission, 'library', self.admission.mapping_inspector.preflight,
                               self.library, self.dependencies, self.admission.job)
            need(preflight is True, 'loader-pre-map-elf-linker-init-confinement')
            self._verify()
            adopted = []
            def adopt(mapping):
                need(not adopted and mapping is not None, 'loader-mapping-adoption')
                self.mappings.append(mapping)
                adopted.append(mapping)
            try:
                authenticate(self.admission, self.authority, 'library')
                mapping = self.backend.map_fd(descriptor, adopt)
                need(len(adopted) == 1 and mapping is adopted[0], 'loader-unadopted-mapping')
                authenticate(self.admission, self.authority, 'library')
            except BaseException as error:
                record(self.authority, error)
                self.failed = True
                self.uncertainties.append('mapping-constructor')
                uncertain(self.authority, self.admission, 'library-mapping', self.admission.library_row['path'])
                raise
            self._verify()
            self._mapping_proof(mapping)
            api = action(self.authority, self.admission, 'library', self.backend.declare, mapping, self.admission.ABI)
            need(api is mapping and all(callable(getattr(api, name, None)) for name in ABI['signatures']), 'loader-closed-api')
            self._verify()
            self._mapping_proof(mapping)
            authenticate(self.admission, self.authority, 'library')
            self._API = api
            return api
        except BaseException as error:
            self.failed = True
            record(self.authority, error)
            raise

    def _mapping_proof(self, mapping):
        result = action(self.authority, self.admission, 'library', self.admission.mapping_inspector.verify,
                        mapping, self.library, self.dependencies, self.admission.job)
        need(result is True, 'loader-fresh-mapping-closure-proof')

    def close(self):
        """There is no approved unmapper. Keep mapping and owners for Root cleanup.

        Even at original J, this method issues no C/linker/FD action. Positive
        absence of these mappings cannot be inferred from closing an Artifact.
        """
        try:
            authenticate(self.admission, self.authority, 'cleanup')
            need(not self.mappings and not self.uncertainties, 'loader-mapping-retained-unmapping-not-admitted')
            return True
        except BaseException as error:
            record(self.authority, error, cleanup=True)
            raise
