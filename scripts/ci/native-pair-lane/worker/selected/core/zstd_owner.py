"""PAIR-ZSTD-OWNER proposal. No loader selection, process, or ambient fallback.

The caller supplies two authenticated, live named/FD owners and one explicit
loader with a separately reviewed linkage grant. Neither owner is closed here.
Only the allocated streaming context belongs to this function. Real loading and
C calls are actors; this proposal's controls substitute the complete C API.
"""
import ctypes
import hashlib

COMPRESSED_LIMIT = 4 * 1024 * 1024
DECODED_LIMIT = 8 * 1024 * 1024
CHUNK = 65536
CALL_LIMIT = 512
READ_CALL_LIMIT = 128
CONTEXT_LIMIT = 4
RETAINED_CONTEXTS = []
LIBRARY_PIN = {
    'path': 'usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5',
    'canonical_path': '/usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5',
    'size': 657432, 'mode': 0o644,
    'sha256': 'fe726238b170b83aa83bf1f8a79109b8b61b9eb45234304511d093bbe5f5fb20',
}


class Input(ctypes.Structure):
    _fields_ = [('src', ctypes.c_void_p), ('size', ctypes.c_size_t), ('pos', ctypes.c_size_t)]


class Output(ctypes.Structure):
    _fields_ = [('dst', ctypes.c_void_p), ('size', ctypes.c_size_t), ('pos', ctypes.c_size_t)]


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def _record(authority, error, cleanup=False):
    # A diagnostic callback cannot replace the exact original exception.
    try:
        authority.record_failure(error, cleanup=cleanup)
    except BaseException:
        pass


def _action(authority, callback, *args):
    authority.check()
    value = callback(*args)
    authority.check()
    return value


def decode(artifact, library, authority, *, loader):
    """Return one bounded frame as bytes, retaining caller J/E and first cause.

    Library.path is root-relative beneath the separately admitted held / root.
    The canonical ARM observation is retained in LIBRARY_PIN, not inferred from
    an arbitrary filesystem root. Owner.verify binds descriptor and ancestors to its original
    authenticated immutable row. Loader receives only that held FD, not a path.
    It must be explicitly admitted with the pinned library/dependency closure;
    this API intentionally supplies no ctypes.CDLL default.
    """
    stream, functions, first, decoded, context = None, {}, None, None, None
    try:
        authority.check()
        need(authority.execution_granted is True, 'root-loader-grant-pending')
        need(type(artifact.size) is int and 6 <= artifact.size <= COMPRESSED_LIMIT,
             'compressed-bound')
        need(type(artifact.sha256) is str and len(artifact.sha256) == 64, 'compressed-pin')
        need(library.size == LIBRARY_PIN['size'] and library.sha256 == LIBRARY_PIN['sha256']
             and library.path == LIBRARY_PIN['path'] and library.mode == LIBRARY_PIN['mode'],
             'library-pin')
        _action(authority, artifact.verify)
        _action(authority, library.verify)
        _action(authority, artifact.rewind)
        raw, reads = bytearray(), 0
        while len(raw) < artifact.size:
            reads += 1
            need(reads <= READ_CALL_LIMIT, 'compressed-read-bound')
            chunk = _action(authority, artifact.read, min(CHUNK, artifact.size - len(raw)))
            need(type(chunk) is bytes and 0 < len(chunk) <= min(CHUNK, artifact.size - len(raw)),
                 'compressed-read')
            raw.extend(chunk)
        need(_action(authority, artifact.read, 1) == b'', 'compressed-tail')
        need(hashlib.sha256(raw).hexdigest() == artifact.sha256, 'compressed-pin')
        _action(authority, artifact.verify)
        # Normal single frame, no dictionaries, reserved or unused descriptor bits.
        need(raw[:4] == b'\x28\xb5\x2f\xfd' and not raw[4] & 0x1b, 'zstd-frame')
        descriptor = library.fd
        need(type(descriptor) is int and descriptor >= 0, 'library-fd')
        api = _action(authority, loader, descriptor)
        _action(authority, library.verify)
        declarations = {
            'ZSTD_createDStream': ([], ctypes.c_void_p),
            'ZSTD_initDStream': ([ctypes.c_void_p], ctypes.c_size_t),
            'ZSTD_DCtx_setParameter': ([ctypes.c_void_p, ctypes.c_int, ctypes.c_int], ctypes.c_size_t),
            'ZSTD_decompressStream': ([ctypes.c_void_p, ctypes.POINTER(Output), ctypes.POINTER(Input)], ctypes.c_size_t),
            'ZSTD_freeDStream': ([ctypes.c_void_p], ctypes.c_size_t),
            'ZSTD_isError': ([ctypes.c_size_t], ctypes.c_uint),
        }
        for name, (args, result) in declarations.items():
            function = _action(authority, getattr, api, name)
            function.argtypes, function.restype = args, result
            functions[name] = function

        def checked(value):
            need(type(value) is int and 0 <= value < 2 ** (8 * ctypes.sizeof(ctypes.c_size_t)), 'zstd-result')
            error = _action(authority, functions['ZSTD_isError'], value)
            need(type(error) is int and error == 0, 'zstd-error')
            return value

        # Save the returned resource before a post-call cancellation check.
        authority.check()
        need(len(RETAINED_CONTEXTS) < CONTEXT_LIMIT, 'zstd-retained-context-bound')
        stream = functions['ZSTD_createDStream']()
        need(type(stream) is int and 0 < stream < 2 ** (8 * ctypes.sizeof(ctypes.c_void_p)), 'zstd-context')
        context = {'stream': stream, 'state': 'OWNED', 'reason': None,
                   'authority': authority, 'artifact': artifact, 'library': library, 'functions': functions}
        RETAINED_CONTEXTS.append(context)
        authority.check()
        checked(_action(authority, functions['ZSTD_initDStream'], stream))
        need(checked(_action(authority, functions['ZSTD_DCtx_setParameter'], stream, 100, 23)) == 0,
             'zstd-window')
        output_bytes, offset, incoming, source = bytearray(), 0, None, None
        for _ in range(CALL_LIMIT):
            authority.check()
            if incoming is None or incoming.pos == incoming.size:
                chunk = bytes(raw[offset:offset + CHUNK])
                offset += len(chunk)
                source = ctypes.create_string_buffer(chunk, max(1, len(chunk)))
                incoming = Input(ctypes.cast(source, ctypes.c_void_p), len(chunk), 0)
            capacity = min(CHUNK, DECODED_LIMIT + 1 - len(output_bytes))
            target = ctypes.create_string_buffer(capacity)
            outgoing = Output(ctypes.cast(target, ctypes.c_void_p), capacity, 0)
            previous = incoming.pos
            code = checked(_action(authority, functions['ZSTD_decompressStream'], stream,
                                   ctypes.byref(outgoing), ctypes.byref(incoming)))
            need(previous <= incoming.pos <= incoming.size and outgoing.pos <= outgoing.size, 'zstd-buffer')
            output_bytes.extend(target.raw[:outgoing.pos])
            need(len(output_bytes) <= DECODED_LIMIT, 'decoded-bound')
            if code == 0:
                need(incoming.pos == incoming.size and offset == len(raw), 'zstd-trailing')
                decoded = bytes(output_bytes)
                break
            need(incoming.pos > previous or outgoing.pos > 0, 'zstd-progress')
        need(decoded is not None, 'zstd-call-bound')
        _action(authority, artifact.verify)
        _action(authority, library.verify)
    except BaseException as error:
        first = error
        _record(authority, error)
    finally:
        if context is not None:
            def cleanup_failure(error, reason):
                nonlocal first
                _record(authority, error, cleanup=True)
                if first is None:
                    first = error
                if context['state'] != 'RETIRED':
                    context['state'] = 'UNCERTAIN'
                context['reason'] = reason

            def cleanup_action(callback):
                # A failed original-J guard is a hard eligibility stop. Merely
                # recording the failure does not authorize the following call.
                try:
                    authority.check(cleanup=True)
                except BaseException as error:
                    cleanup_failure(error, 'GUARD')
                    return False, None
                try:
                    result = callback()
                except BaseException as error:
                    cleanup_failure(error, 'CALL')
                    return False, None
                try:
                    authority.check(cleanup=True)
                except BaseException as error:
                    cleanup_failure(error, 'LATE')
                    return False, None
                return True, result

            def free_owned():
                code = functions['ZSTD_freeDStream'](stream)
                need(type(code) is int and code == 0, 'zstd-free')

            if cleanup_action(free_owned)[0]:
                context['state'] = 'RETIRED'
                RETAINED_CONTEXTS.remove(context)
                # Metadata verification is separate from context retirement.
                # Each action requires a fresh original-J eligibility check;
                # if it fails, no subsequent action starts. Owner guards still
                # enforce their own original E and immutable first cause.
                for item in (artifact, library):
                    eligible, verify = cleanup_action(lambda: getattr(item, 'verify'))
                    if not eligible or not cleanup_action(verify)[0]:
                        break
    if first is not None:
        raise first
    try:
        authority.check()
    except BaseException as error:
        _record(authority, error)
        raise
    return decoded
