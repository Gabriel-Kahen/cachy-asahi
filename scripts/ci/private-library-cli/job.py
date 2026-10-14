# SPDX-License-Identifier: MIT
"""Trusted standalone coordinator. Importing this file performs no actors.

The external Root plan pins this body, the Source/Data snapshots and tools.
The interpreter, Linux, ordinary imports and local Docker daemon are trusted.
Private inputs and results are never workflow artifacts or public log bodies.
"""
from contextlib import redirect_stdout, redirect_stderr
import base64
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time

CLI = 'scripts/ci/private-library-cli/'
PREFIX = 'CACHY_OLD_FOUR_'
INPUT_PIN = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
INTEGRATION_PIN = '5d0f6b1d335c1949965699d4db6658af313af8977079e9a6464f0e5db4071ed3'
SEEDS = (
    ('jbigkit-2.1-8-aarch64.pkg.tar.xz', 48816, 'ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db', 'JBIGKIT', 2),
    ('jbigkit-2.1-8-aarch64.pkg.tar.xz.sig', 566, 'f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f', 'JBIGKIT_SIG', 1),
    ('libtiff-4.7.2-1-aarch64.pkg.tar.xz', 354480, '02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd', 'LIBTIFF', 15),
    ('libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig', 566, '8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa', 'LIBTIFF_SIG', 1))
SEED_NAMES = frozenset(PREFIX + name + '_' + str(n).zfill(2)
    for _, _, _, name, count in SEEDS for n in range(1, count + 1)) | {PREFIX+'SCHEMA', PREFIX+'SOURCE_EPOCH'}
WORKFLOW = '.github/workflows/native-arm-runner-observation.yml'
RETAINED = []


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def check(end):
    need(time.monotonic() < end, 'ORIGINAL_JOB_DEADLINE')


def node(row):
    return [getattr(row, key) for key in ('st_dev','st_ino','st_mode','st_nlink',
        'st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')]


def regular(path, cap=8*1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         all(not part.is_symlink() for part in (path, *path.parents)), 'JOB_REGULAR_PATH')
    fd = os.open(path, os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    first = None
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
             'JOB_REGULAR_TYPE_CAP')
        chunks, count = [], 0
        while True:
            part = os.read(fd, min(65536, cap+1-count))
            if not part: break
            count += len(part); need(count <= cap, 'JOB_REGULAR_CAP'); chunks.append(part)
        need(count == before.st_size and node(before) == node(os.fstat(fd)) == node(path.lstat()),
             'JOB_REGULAR_CHANGED')
        return b''.join(chunks)
    except BaseException as error:
        first = error; raise
    finally:
        try: os.close(fd)
        except BaseException as error:
            if first is None: raise
            first.add_note('JOB_READ_CLOSE_UNCERTAIN:'+type(error).__name__)


def create(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, mode)
    first = None
    try:
        at = 0
        while at < len(raw):
            n = os.write(fd, raw[at:at+65536]); need(n > 0, 'JOB_SHORT_WRITE'); at += n
        os.fsync(fd); os.fchmod(fd, mode)
    except BaseException as error:
        first = error; raise
    finally:
        try: os.close(fd)
        except BaseException as error:
            if first is None: raise
            first.add_note('JOB_WRITE_CLOSE_UNCERTAIN:'+type(error).__name__)
    return dict(path=str(path), sha256=sha(raw), bytes=len(raw), identity=node(Path(path).lstat()))


def capsule(source, target, rows, end, *, readonly=True):
    """Copy exact Root-selected bytes. Original producer needs original modes."""
    need(8 <= len(rows) <= 512 and sum(row['bytes'] for row in rows.values()) <= 64*1024**2,
         'JOB_SOURCE_SET_CAP')
    target.mkdir(mode=0o700)
    selected = {}
    for name, row in sorted(rows.items()):
        check(end)
        need(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts and
             set(row) == {'sha256','bytes','mode'} and row['mode'] in (0o644,0o755), 'JOB_SOURCE_ROW')
        origin = source/name; raw = regular(origin)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'] and
             stat.S_IMODE(origin.lstat().st_mode) == row['mode'], 'JOB_SOURCE_CORRESPONDENCE')
        destination = target/name; destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        mode = row['mode'] & ~0o222 if readonly else row['mode']
        create(destination, raw, mode)
        selected[name] = dict(sha256=row['sha256'], bytes=row['bytes'], mode=mode)
    for directory in sorted((p for p in target.rglob('*') if p.is_dir()), reverse=True):
        directory.chmod(0o500)
    target.chmod(0o500)
    check(end)
    return selected


def consume_seeds(supplied, cache, input_path, end):
    """Detach every named chunk, validate exact frozen pins, create only fresh files.

    Clearing the dictionaries is environment hygiene, not memory zeroization.
    """
    values = dict(supplied); supplied.clear()
    leaked = [key for key in os.environ if key.startswith(PREFIX)]
    for key in leaked:os.environ.pop(key)
    created = []
    first = None
    try:
        need(not leaked, 'SEED_ESCAPED_BOOTSTRAP_DETACHMENT')
        need(set(values) == SEED_NAMES and values[PREFIX+'SCHEMA'] == '1' and
             values[PREFIX+'SOURCE_EPOCH'] == '1791748800', 'EXACT_NINETEEN_SEED_CHUNKS')
        need(sha(regular(input_path)) == INPUT_PIN, 'SEED_FROZEN_INPUTS')
        info = cache.lstat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
             info.st_uid == os.getuid() and info.st_gid == os.getgid() and not any(cache.iterdir()),
             'FRESH_PRIVATE_SEED_CACHE')
        for filename, size, pin, name, count in SEEDS:
            check(end)
            chunks = [values.pop(PREFIX+name+'_'+str(n).zfill(2)) for n in range(1,count+1)]
            need(all(type(s) is str and 0 < len(s) <= 32768 for s in chunks) and
                 all(len(s) == 32768 for s in chunks[:-1]), 'SEED_CANONICAL_CHUNK_LENGTH')
            wire = ''.join(chunks)
            need(len(wire) == 4*((size+2)//3), 'SEED_ENCODED_SIZE')
            raw = base64.b64decode(wire, validate=True)
            need(len(raw) == size and sha(raw) == pin and
                 base64.b64encode(raw).decode('ascii') == wire, 'SEED_FROZEN_BYTES')
            path = cache/filename; ref = create(path, raw)
            created.append((path, ref['identity']))
            need(ref['identity'][3] == 1 and ref['identity'][4:6] == [os.getuid(),os.getgid()] and
                 stat.S_IMODE(ref['identity'][2]) == 0o600, 'OWNED_PRIVATE_SEED_FILE')
        check(end)
        return {'schema_version':1,'objects':4,'chunks':19,'decoded_bytes':404428,
                'frozen_inputs_sha256':INPUT_PIN,'environment_detached':True}
    except BaseException as error:
        first = error
        for path, identity in reversed(created):
            try:
                need(node(path.lstat()) == identity, 'SEED_CREATION_IDENTITY_CHANGED')
                path.unlink()
            except BaseException as cleanup:
                first.add_note('SEED_OWNED_CLEANUP_UNCERTAIN:'+type(cleanup).__name__)
        raise
    finally:
        values.clear()


class PrivateText(io.TextIOBase):
    """Bound original Python summaries before writing to a private descriptor."""
    def __init__(self, path):
        self.fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        self.count = 0

    def write(self, value):
        raw = value.encode('utf-8'); self.count += len(raw)
        need(self.count <= 4*1024**2, 'ORIGINAL_PYTHON_LOG_CAP')
        at = 0
        while at < len(raw):
            n = os.write(self.fd, raw[at:at+65536]); need(n > 0,'ORIGINAL_PYTHON_LOG_WRITE'); at += n
        return len(value)

    def flush(self):
        if self.fd is not None: os.fsync(self.fd)

    def close(self):
        if self.fd is not None:
            self.flush(); fd,self.fd = self.fd,None; os.close(fd)
        super().close()


def initial_kind(error):
    if error is None:return 'NO_FIRST_OBSERVED'
    names = ((ValueError,'VALUE_ERROR'),(OSError,'OS_ERROR'),(TypeError,'TYPE_ERROR'),(KeyError,'KEY_ERROR'),
             (TimeoutError,'TIMEOUT_ERROR'),(KeyboardInterrupt,'KEYBOARD_INTERRUPT'),(SystemExit,'SYSTEM_EXIT'))
    for cls, name in names:
        if type(error) is cls:return name
    return 'OTHER_EXCEPTION' if isinstance(error,Exception) else 'OTHER_CONTROL'


def retain_initial_control(first, secondary):
    """Retain the original throw and any diagnostic control without formatting."""
    if isinstance(secondary,Exception):return 'NONE'
    if first is not None and first is not secondary:
        prior = first.__cause__
        first.__cause__ = secondary if prior is None else BaseExceptionGroup('initial diagnostic controls',[prior,secondary])
        first.__suppress_context__ = True
    RETAINED.append(dict(kind='INITIAL_DIAGNOSTIC_CONTROL',first=first,secondary=secondary))
    return 'KEYBOARD_INTERRUPT' if type(secondary) is KeyboardInterrupt else 'SYSTEM_EXIT' if type(secondary) is SystemExit else 'OTHER_CONTROL'


def initial_failure_snapshot(identity, rows, boundary, initial_first, first, detail, original, log, record,
                             original_returned, original_code, terminal, cleanup, secondary_control):
    """Already-held observations only; NOT_OBSERVED makes no absence claim."""
    binding = {key:identity[key] for key in ('code_commit','source_commit','data_commit','run_id','run_attempt')}
    binding.update(job_sha256=rows[CLI+'job.py']['sha256'],publication_sha256=rows[CLI+'publication.py']['sha256'])
    status = terminal.get('status') if type(terminal) is dict else None
    status = status if type(status) is str and status in ('PRIVATE_CHECKED','INCOMPLETE','FAIL') else 'NOT_OBSERVED'
    pin, count = (None,None) if detail is None else (detail['detail_sha256'],detail['detail_bytes'])
    if type(count) is not int or not 0 <= count <= 65536:pin,count=None,None
    return dict(schema_version=1,binding=binding,stage=boundary[0],operation=boundary[1],
        tag_basis='FIRST_FAILURE' if initial_first is not None else 'LAST_ENTERED_NO_FIRST',
        first_kind=initial_kind(initial_first),job_first_kind=initial_kind(first),
        detail_sha256=pin,detail_bytes=count,original_observation='PRESENT' if original is not None else 'NOT_OBSERVED',
        private_log_observation='PRESENT' if log is not None else 'NOT_OBSERVED',
        consumer_record_observation='PRESENT' if record is not None else 'NOT_OBSERVED',
        original_exit_code=original_code if original_returned else None,terminal_status=status,
        raw_cleanup=dict(cleanup),secondary_control=secondary_control)


def run(context):
    """Issue registration, execute the supervised original plus child, finalize."""
    plan, earliest = context['plan'], context['earliest_entry']
    need(type(earliest) in (int,float) and 0 < earliest <= time.monotonic(), 'EARLIEST_JOB_CLOCK')
    end = earliest+10800; cutoff = min(end-120,earliest+10080); check(cutoff)
    source, private = Path(context['source_root']), Path(context['private_root'])
    rows = context['source_rows']['files']
    own = CLI+'job.py'
    need(sha(regular(Path(__file__).absolute())) == rows[own]['sha256'], 'ISSUED_COORDINATOR_BODY')
    selected = capsule(source,private/'library-source',rows,cutoff)
    module_path = private/'library-source'/CLI
    # Bootstrap imports only this standalone stdlib-only coordinator. All other
    # selected CLI modules originate in the private pinned capsule.
    names = ('boundary','parent_bridge','owned_build','baseline_bridge','operations',
             'evidence','consumer_adapter','producer_supervisor','publication')
    need(not any(name in sys.modules for name in names), 'PRELOADED_CLI_MODULE_REFUSED')
    sys.path.insert(0,str(module_path))
    modules = {name:importlib.import_module(name) for name in names}
    boundary, bridge = modules['boundary'], modules['parent_bridge']
    publication, supervisor = modules['publication'], modules['producer_supervisor']
    environment = context['environment']; identity = dict(
        repository=plan['repository'],workflow=WORKFLOW,ref=plan['ref'],
        code_commit=plan['code_commit'],source_commit=plan['source_commit'],data_commit=plan['data_commit'],
        packet_sha256=plan['source_rows']['sha256'],peer_sha256=plan['peer_receipt']['sha256'],
        plan_sha256=context['plan_sha256'],run_id=environment['GITHUB_RUN_ID'],
        run_attempt=environment['GITHUB_RUN_ATTEMPT'])
    nonce = secrets.token_hex(16)
    clock = dict(schema_version=1,purpose='development-workflow-clock',source_commit=plan['source_commit'],
        run_id=identity['run_id'],run_attempt=identity['run_attempt'],nonce=nonce,
        issued_monotonic=earliest,deadline_monotonic=end,allowance_seconds=10800,
        clock_domain=bridge.clock_domain(),issuer_source_sha256=rows[own]['sha256'],
        issuer_workflow_commit=environment['GITHUB_WORKFLOW_SHA'])
    boundary.validate_clock(clock,identity,bridge.clock_domain())
    cache = private/'cache'; cache.mkdir(mode=0o700)
    output = private/'library-output'
    public_output = private/'publication'
    report = {}; original = None; original_code = 1; terminal = record = None
    uncertainties, cancelled, baseline_absent = 0, False, False
    producer_closed = False; first = None; log = None
    initial_boundary = ('ORIGINAL_PREPARATION','INTEGRATION_LOCK_READ')
    failure_boundary = None; initial_first = None; original_returned = False; diagnostic_cancelled = False
    detail = None; secondary_control = 'NONE'; initial_failure = None
    saved_environment = dict(os.environ)
    try:
        initial_boundary = ('ORIGINAL_PREPARATION','INTEGRATION_LOCK_READ')
        integration_raw = regular(source/'scripts/ci/integration.lock.json')
        initial_boundary = ('ORIGINAL_PREPARATION','INTEGRATION_LOCK_VALIDATE')
        need(sha(integration_raw) == INTEGRATION_PIN, 'ORIGINAL_INTEGRATION_LOCK')
        original_rows = json.loads(integration_raw)['source_files']
        need(len(original_rows) == 159, 'ORIGINAL_159_SOURCE_SET')
        original_rows = {name:dict(row,bytes=rows[name]['bytes']) for name,row in original_rows.items()}
        name = 'scripts/ci/integration.lock.json'; original_rows[name] = rows[name]
        original_root = private/'original-source'
        initial_boundary = ('ORIGINAL_PREPARATION','ORIGINAL_SOURCE_CAPSULE')
        capsule(source,original_root,original_rows,cutoff,readonly=False)
        initial_boundary = ('SEED_INTAKE','SEED_DECODE')
        seed_receipt = consume_seeds(context['seed_environment'],cache,original_root/'scripts/ci/inputs.lock.json',cutoff)
        initial_boundary = ('SEED_INTAKE','SEED_RECEIPT_WRITE')
        create(private/'seed-intake.json',encoded(seed_receipt))
        clean = dict(PATH='/usr/bin:/bin',DOCKER_HOST='unix:///run/docker.sock',DOCKER_BUILDKIT='0',
                     LC_ALL='C',GITHUB_SHA=plan['source_commit'],PYTHONDONTWRITEBYTECODE='1')
        initial_boundary = ('RUNTIME_BINDING','ENVIRONMENT_DIRECTORIES')
        for key,leaf in (('HOME','home'),('DOCKER_CONFIG','docker-config'),('TMPDIR','tmp')):
            directory = private/leaf; directory.mkdir(mode=0o700); clean[key]=str(directory)
        initial_boundary = ('RUNTIME_BINDING','DAEMON_SOCKET')
        socket = Path('/run/docker.sock').lstat()
        tool_pins = {key:dict(plan['tools'][key]) for key in ('interpreter','docker','gpgv')}
        tool_pins['socket'] = dict(path='/run/docker.sock',identity=[socket.st_dev,socket.st_ino,
            socket.st_mode,socket.st_uid,socket.st_gid,socket.st_nlink])
        initial_boundary = ('RUNTIME_BINDING','RUNTIME_OBSERVE')
        modules['consumer_adapter'].observe_runtime(tool_pins,cutoff)
        initial_boundary = ('REGISTRATION','PRODUCER_SOURCE_ROWS')
        producer_sources = {}
        for key in ('native_arm','integration'):
            name = 'scripts/ci/'+key+'.py'; row = original_rows[name]
            producer_sources[key] = dict(path=str(original_root/name),**row)
        initial_boundary = ('REGISTRATION','CLOCK_RECORD')
        clock_ref = create(private/'clock.json',encoded(clock),0o444)
        initial_boundary = ('REGISTRATION','ROOT_SELECTION_VALIDATE')
        selection = dict(schema_version=1,purpose='project-libraries-cli-root-selection',identity=identity,
            nonce=nonce,clock=clock_ref,original_entry_monotonic=earliest,
            sources=dict(root=str(private/'library-source'),files=selected,manifest_sha256=sha(boundary.encoded(selected))),
            inputs=plan['metadata'],producer_sources=producer_sources,tool_pins=tool_pins,
            environment=clean,output_path=str(output),credentials=dict(uid=os.getuid(),gid=os.getgid()),cache_path=str(cache))
        modules['consumer_adapter'].selection_shape(selection)
        initial_boundary = ('REGISTRATION','SELECTION_WRITE')
        pin = create(private/'selection.json',boundary.encoded(selection),0o444)
        initial_boundary = ('REGISTRATION','PRIVATE_LOG_OPEN')
        log = PrivateText(private/'original-python.log')
        producer_environment = {key:value for key,value in clean.items() if not key.startswith('DOCKER_')}
        os.environ.clear(); os.environ.update(producer_environment)
        with redirect_stdout(log),redirect_stderr(log):
            initial_boundary = ('ORIGINAL_EXECUTION','PRODUCER_ENTER')
            with supervisor.Producer(original_root,original_rows,clock,earliest,producer_environment,private,
                                     source_checkout=source) as original:
                try:
                    initial_boundary = ('ORIGINAL_EXECUTION','RUN_ORIGINAL')
                    original_code,terminal = modules['consumer_adapter'].run_original(pin,
                        {key:original.modules[key] for key in ('native_arm','integration')},cache=cache,
                        native_output=private/'native-output',integration_output=private/'integration-output',report=report)
                    original_returned = True
                except BaseException as error:
                    try:
                        initial_first = error; failure_boundary = initial_boundary
                    except BaseException as secondary:
                        control = retain_initial_control(error,secondary)
                        initial_first = error; failure_boundary = initial_boundary
                        if control != 'NONE':secondary_control = control; diagnostic_cancelled = True
                    raise
                finally:
                    initial_boundary = ('BASELINE_RETIREMENT','CONSUMER_STATE')
                    consumer = report.get('consumer')
                    record = consumer.record if consumer is not None else None
                    terminal = consumer.result if consumer is not None else terminal
                    # Unknown retirement retains cache/image/lease and process
                    # handles. Never delete borrowed state on that path.
                    registration = consumer.registration if consumer is not None else None
                    retained = bool(registration is not None and getattr(registration,'retained',False))
                    if not retained and not bridge.HELD:
                        initial_boundary = ('BASELINE_RETIREMENT','BASELINE_RETIRE')
                        baseline_absent = original.cleanup_baseline(private/'native-output')
                    else:
                        uncertainties += 1
                    initial_boundary = ('FINALIZATION','PRODUCER_EXIT')
            producer_closed = original.closed
    except BaseException as error:
        first = error; cancelled = isinstance(error,KeyboardInterrupt)
        try:
            if initial_first is None and failure_boundary is None:
                initial_first = error; failure_boundary = initial_boundary
        except BaseException as secondary:
            uncertainties += 1
            control = retain_initial_control(first,secondary)
            if initial_first is None and failure_boundary is None:
                initial_first = error; failure_boundary = initial_boundary
            if control != 'NONE':secondary_control = control; diagnostic_cancelled = True
        uncertainties += 1
        RETAINED.append(dict(kind='JOB_FIRST_CAUSE',error=error,producer=original,report=report))
    finally:
        context['seed_environment'].clear()
        for key in tuple(os.environ):
            if key.startswith(PREFIX):os.environ.pop(key)
        os.environ.clear(); os.environ.update({k:v for k,v in saved_environment.items() if not k.startswith(PREFIX)})
        saved_environment.clear()
        if log is not None:
            try:
                initial_boundary = ('FINALIZATION','PRIVATE_LOG_CLOSE')
                log.close()
            except BaseException as error:
                uncertainties += 1
                if first is None:
                    first=error
                    try:
                        initial_first=error; failure_boundary=initial_boundary
                    except BaseException as secondary:
                        control = retain_initial_control(first,secondary)
                        initial_first = error; failure_boundary = initial_boundary
                        if control != 'NONE':secondary_control = control; diagnostic_cancelled = True
        if original is not None:
            producer_closed = original.closed
            cancelled = cancelled or original.cancelled
            uncertainties += len(original.uncertainties)
    cancelled = cancelled or diagnostic_cancelled
    cleanup = dict(schema_version=1,status='PASS' if not uncertainties and producer_closed and baseline_absent else 'FAIL',
        baseline_image_absent=baseline_absent,producer_closed=producer_closed,cancelled=cancelled,
        uncertainties=uncertainties+len(bridge.HELD))
    if first is not None:
        try:
            raw_detail = str(first).encode()
            detail = dict(schema_version=1,exception_type=type(first).__name__,
                detail_sha256=sha(raw_detail),detail_bytes=len(raw_detail),cancelled=cancelled)
            create(private/'job-failure.json',encoded(detail))
        except BaseException as secondary:
            cleanup['status'] = 'FAIL'; cleanup['uncertainties'] += 1
            control = retain_initial_control(first,secondary)
            if control != 'NONE':
                secondary_control = control
                cancelled = True; cleanup['cancelled'] = True
                cleanup['status'] = 'FAIL'
    try:
        if ((initial_first is None) == (failure_boundary is None)) and (first is not None or
            record is None or original_code != 0 or type(terminal) is not dict or
            type(terminal.get('status')) is not str or terminal['status'] != 'PRIVATE_CHECKED' or
            cleanup['status'] != 'PASS' or not cleanup['baseline_image_absent'] or
            not cleanup['producer_closed'] or cleanup['cancelled'] or cleanup['uncertainties']):
            initial_failure = initial_failure_snapshot(identity,rows,failure_boundary or initial_boundary,
                initial_first,first,detail,original,log,record,original_returned,original_code,terminal,cleanup,secondary_control)
    except BaseException as secondary:
        control = retain_initial_control(first,secondary)
        if control != 'NONE':
            if first is None:first = secondary
            secondary_control = control
            cancelled = True; cleanup['cancelled'] = True
            cleanup['status'] = 'FAIL'; cleanup['uncertainties'] += 1
    if record is None:
        return publication.emit_failure(identity,clock,selection['sources'] if 'selection' in locals() else dict(
            root=str(private/'library-source'),files=selected,manifest_sha256=sha(boundary.encoded(selected))),
            cleanup,public_output,sys.stdout,child_output=output,producer_root=private/'original-source',first_error=first,initial_failure=initial_failure)['exit_code']
    public_context = publication.Context(record,producer_root=private/'original-source')
    if first is not None:public_context.fail(first)
    result = publication.publish(public_context,
        terminal,original_code,cleanup,clock,public_output,sys.stdout,initial_failure=initial_failure)
    return result['exit_code']
