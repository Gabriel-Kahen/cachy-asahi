"""Source-only deadline-corrected guardian. Exact Root closure remains unselected."""
import time
ORIGINAL_ENTRY = time.monotonic()  # before preflight and remaining imports
import hashlib
import json
import math
import os
import resource
import selectors
import signal
import stat
import subprocess
import threading

CAP = 1048576
LIVE = {}  # retain unreaped Popen objects; their destructor must not release ownership


class Refusal(Exception):
    pass


def endpoints(entered, work_end, end):
    if not all(type(v) in (int, float) and math.isfinite(v) for v in (entered, work_end, end)):
        raise Refusal('CLOCK_NONFINITE')
    if not entered < work_end <= end - 4 or end - entered > 304:
        raise Refusal('CLOCK_ENVELOPE')


def structural(raw, expected_pid):
    # comm may contain spaces and parentheses; it is never retained or interpreted.
    if len(raw) > 4096:
        raise Refusal('PROC_STAT_LIMIT')
    left, right = raw.find(b'('), raw.rfind(b')')
    fields = raw[right + 2:].split()
    if type(expected_pid) is not int or expected_pid <= 0 or raw[:left] != f'{expected_pid} '.encode() or right <= left or raw[right + 1:right + 2] != b' ' or len(fields) < 20:
        raise Refusal('PROC_STAT_SHAPE')
    state = fields[0].decode('ascii')
    if state not in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'x', 'I', 'P', 'W'):
        raise Refusal('PROC_STATE')
    ppid, pgrp, session, start = (int(fields[i]) for i in (1, 2, 3, 19))
    if min(ppid, pgrp, session) < 0 or start <= 0:
        raise Refusal('PROC_NUMERIC_SHAPE')
    return (expected_pid, ppid, pgrp, session, state, start)


def disposition(terminal, rows, token):
    # token = (pid, startticks); rows contain only pid/ppid/pgrp/session/state/startticks.
    pid, start = token
    leader = [r for r in rows if r[0] == pid]
    if len(leader) != 1 or leader[0][2:4] != (pid, pid) or leader[0][5] != start:
        raise Refusal('LEADER_OWNERSHIP_UNKNOWN')
    if terminal is not None and leader[0][4] != 'Z':
        raise Refusal('TERMINAL_LEADER_NOT_UNREAPED_ZOMBIE')
    residue = [r for r in rows if r[0] != pid and (r[2] == pid or r[3] == pid)]
    if any(r[2] != pid or r[3] != pid for r in residue):
        raise Refusal('SESSION_GROUP_ESCAPE')
    return not residue and terminal is not None


def source_bindings(frame):
    """Mandatory exact byte roles; neither flags nor their hashes confer admission."""
    roles = {'invocation_owner', 'query_successor', 'nested_runtime', 'nested_gate',
             'publisher', 'waitability_result', 'blocking_operations_contract'}
    bindings = frame.get('source_bindings')
    if not isinstance(bindings, dict) or set(bindings) != roles:
        raise Refusal('EXACT_ROOT_SOURCE_BINDINGS_MISSING')
    for row in bindings.values():
        if not isinstance(row, dict) or set(row) != {'path', 'bytes', 'mode', 'sha256'} or not isinstance(row['path'], str) or not row['path'].startswith('/') or type(row['bytes']) is not int or row['bytes'] <= 0 or type(row['mode']) is not int or not isinstance(row['sha256'], str) or len(row['sha256']) != 64 or any(c not in '0123456789abcdef' for c in row['sha256']):
            raise Refusal('EXACT_ROOT_SOURCE_BINDING_SHAPE')
        if row not in frame['raw_source']:
            raise Refusal('ROOT_BINDING_NOT_IN_PINNED_CUSTODY')
    return bindings


def supervise(io, frame, nested_gate):
    """Finite policy; tests substitute inert io. No inferred PID on partial birth."""
    entered, work_end, end = frame['entered'], frame['work_end'], frame['end']
    endpoints(entered, work_end, end)
    record = dict(status='FAIL', firstcause=None, original_error=None, cancelled=False,
                  cancellation=None, cleanup_error=None, cleanup_verified=False,
                  group_absence_observed=False,
                  natural_exit=False, exit_code=None, pid=None, reaped=False,
                  reap_attempted=False,
                  signals_sent=[], entered=entered, work_end=work_end, end=end,
                  output_bytes=0, birth='NOT_ATTEMPTED', scope='OWNED_PRIVATE_GROUP_ONLY')
    token = None
    terminal = None
    forced = False

    def fail(cause):
        if record['firstcause'] is None:
            record['firstcause'] = cause

    def interrupt(error):
        if isinstance(error, KeyboardInterrupt):
            record['cancelled'] = True
            record['cancellation'] = record['cancellation'] or 'KeyboardInterrupt'
            fail('CANCELLED')

    def clock():
        now = io.now()
        if not math.isfinite(now) or now < entered:
            raise Refusal('CLOCK_OBSERVATION')
        return now

    def cancellation():
        value = io.cancelled()
        if value:
            record['cancelled'] = True
            record['cancellation'] = value
            fail('CANCELLED')
        return bool(value)

    def observe():
        nonlocal terminal
        # WNOWAIT verifies the direct child still exists as an owned child; ECHILD refuses.
        terminal = io.peek(token)
        action_guard()
        rows = io.members(token, end)
        action_guard()
        return disposition(terminal, rows, token)

    def action_guard():
        # Cancellation stays failed, but disposal of a still-owned group remains
        # necessary. Re-observe it before each action; an unknown observation stops
        # action. No late action is authorized by cancellation or cleanup grace.
        cancellation()
        if clock() >= end:
            raise Refusal('ACTION_AFTER_ORIGINAL_END')

    def collect():
        record['output_bytes'] = io.drain(CAP - record['output_bytes']) + record['output_bytes']
        if record['output_bytes'] > CAP:
            raise Refusal('OUTPUT_LIMIT')

    try:
        if cancellation() or clock() >= work_end:
            raise Refusal('PREFLIGHT_CANCEL_OR_DEADLINE')
        io.preflight(frame, work_end)
        if cancellation() or clock() >= work_end:
            raise Refusal('START_CANCEL_OR_DEADLINE')
        record['birth'] = 'ATTEMPTED'
        # Backend assigns its Popen before restoring the parent mask. Token obtained
        # afterwards. If validation fails, cleanup may use only its held child handle.
        io.birth(frame)
        token = io.token(end)
        record.update(pid=token[0], birth='OWNED')
        while True:
            collect()
            if cancellation():
                break
            if clock() >= work_end:
                fail('WORK_DEADLINE')
                break
            empty = observe()
            if cancellation() or clock() >= work_end:
                fail('POST_OBSERVATION_WORK_DEADLINE_OR_CANCEL')
                break
            if terminal is not None:
                record['exit_code'] = terminal
                record['natural_exit'] = True
                if terminal != 0:
                    fail('LEADER_EXIT_NONZERO')
                elif not empty:
                    fail('NATURAL_LEADER_DESCENDANT_RESIDUE')
                else:
                    while not io.eof() and clock() < work_end and not cancellation():
                        collect()
                        if not io.eof():
                            io.pause(min(.02, work_end - clock()))
                    if not io.eof():
                        raise Refusal('OUTPUT_EOF_UNKNOWN')
                    io.postflight(frame, work_end)
                    if nested_gate(frame) is not True:
                        fail('NESTED_SOURCE_GATE_REFUSAL')
                    if cancellation() or clock() >= work_end:
                        fail('NESTED_GATE_WORK_DEADLINE_OR_CANCEL')
                break
            io.pause(min(.02, work_end - clock()))
    except BaseException as error:
        record['original_error'] = type(error).__name__
        interrupt(error)
        fail(str(error) if isinstance(error, Refusal) else 'ORIGINAL_EXCEPTION')
    finally:
        try:
            cancellation()
            cleanup_entered = clock()
            # These phase cutoffs are fixed once, before potentially slow scans.
            term_end, kill_end = min(end, cleanup_entered + 2), min(end, cleanup_entered + 3)
            if token is None and io.has_child():
                token = io.token(end)
                record.update(pid=token[0], birth='OWNED_AFTER_BIRTH_REFUSAL')
            if token is not None:
                empty = observe()
                action_guard()
                if not empty:
                    fail('GROUP_DISPOSAL_REQUIRED')
                    forced = True
                    for kind, until in (('TERM', term_end), ('KILL', kill_end)):
                        if clock() >= end:
                            break
                        if clock() >= until:
                            continue
                        # Fresh ownership/structural validation immediately before signal.
                        if observe():
                            action_guard()
                            empty = True
                            break
                        action_guard()
                        if clock() >= until:
                            continue
                        io.send_owned(token, kind, end)
                        record['signals_sent'].append(kind)
                        while clock() < until:
                            # Failed capture must never prevent bounded group disposal.
                            # No further output is accepted once the work loop refuses.
                            cancellation()
                            if observe():
                                action_guard()
                                empty = True
                                break
                            action_guard()
                            io.pause(min(.02, until - clock()))
                        if empty:
                            break
                if not empty:
                    fail('GROUP_ABSENCE_UNVERIFIED')
                elif clock() < end:
                    # Final WNOWAIT+membership proof precedes the only releasing wait.
                    if not observe():
                        raise Refusal('FINAL_GROUP_RESIDUE')
                    action_guard()
                    record['group_absence_observed'] = True
                    record['cleanup_verified'] = True
                    record['reap_attempted'] = True
                    record['reaped'] = None  # releasing wait failure has unknown disposition
                    io.reap(token, terminal, end)
                    record['reaped'] = True
                    record['exit_code'] = terminal
                else:
                    fail('FINAL_REAP_DEADLINE')
            elif record['birth'] == 'ATTEMPTED':
                fail('PARTIAL_BIRTH_UNKNOWN')
            else:
                record['cleanup_error'] = 'NO_CHILD_CREATED'
        except BaseException as error:
            interrupt(error)
            record['cleanup_verified'] = False
            record['cleanup_error'] = str(error) if isinstance(error, Refusal) else type(error).__name__
            fail('CLEANUP_UNCERTAIN')
        try:
            io.close_capture()
        except BaseException as error:
            interrupt(error)
            record['cleanup_error'] = record['cleanup_error'] or type(error).__name__
            fail('CAPTURE_CLOSE_FAILED')
    record['ended'] = None
    record['within_envelope'] = False
    try:
        cancellation()
        record['ended'] = clock()
        record['within_envelope'] = record['ended'] < end
        if not record['within_envelope']:
            fail('FINAL_PUBLICATION_DEADLINE')
    except BaseException as error:
        interrupt(error)
        record['cleanup_error'] = record['cleanup_error'] or type(error).__name__
        fail('FINAL_REPORT_UNCERTAIN')
    if record['firstcause'] is None and not forced and not record['cancelled'] and record['natural_exit'] and record['exit_code'] == 0 and record['cleanup_verified'] and record['reaped']:
        record['status'] = 'READY_FOR_ROOT_BOUNDED_PUBLICATION'
    return record


class Linux:
    """Proposed real adapter; this task never instantiates or executes it."""
    def __init__(self):
        self.process = None
        self.selector = selectors.DefaultSelector()
        self.output = [bytearray(), bytearray()]
        self.cancel = None
        self.handlers = {}
        self.sigchld_established = False
        self.birth_started = False

    def now(self):
        return time.monotonic()

    def cancelled(self):
        pending = signal.sigpending()
        if signal.SIGINT in pending or signal.SIGTERM in pending:
            self.cancel = self.cancel or 'PENDING_INT_OR_TERM'
        return self.cancel

    def _handler(self, number, _frame):
        self.cancel = self.cancel or ('INT' if number == signal.SIGINT else 'TERM')

    def preflight(self, frame, deadline):
        if threading.active_count() != 1 or os.name != 'posix':
            raise Refusal('SINGLE_THREAD_LINUX_REQUIRED')
        source_bindings(frame)
        rows = [frame['python'], *frame['raw_source']]
        if not 2 <= len(rows) <= 128 or sum(row['bytes'] for row in rows) > 32 * 1024**2:
            raise Refusal('SOURCE_PIN_TOTAL_BOUND')
        argv = frame['argv']
        if not isinstance(argv, list) or not 1 <= len(argv) <= 256 or any(not isinstance(x, str) or '\0' in x for x in argv) or sum(len(x.encode()) + 1 for x in argv) > 65536:
            raise Refusal('ARGV_BOUND')
        if argv[0] != frame['python']['path']:
            raise Refusal('PYTHON_ARGV_IDENTITY')
        raw_argv = json.dumps(argv, ensure_ascii=True, separators=(',', ':')).encode()
        if hashlib.sha256(raw_argv).hexdigest() != frame['argv_sha256']:
            raise Refusal('ARGV_PIN')
        if frame['env'] != {'PATH': '/usr/bin', 'LC_ALL': 'C'}:
            raise Refusal('ENVIRONMENT_SHAPE')
        context = os.stat(frame['cwd'], follow_symlinks=False)
        if not os.path.isabs(frame['cwd']) or not stat.S_ISDIR(context.st_mode) or context.st_uid != os.getuid() or stat.S_IMODE(context.st_mode) != 0o700:
            raise Refusal('PRIVATE_CWD_SHAPE')
        self._pins(frame, deadline)
        original_chld = signal.getsignal(signal.SIGCHLD)
        if original_chld not in (signal.SIG_DFL, signal.SIG_IGN) and not callable(original_chld):
            raise Refusal('SIGCHLD_ORIGINAL_DISPOSITION_UNKNOWN')
        self.handlers[signal.SIGCHLD] = original_chld
        # Public Linux/CPython default-setting primitive, not cache introspection
        # of C sigaction flags. Its selected-runtime semantics require Root review.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        self.sigchld_established = True
        for number in (signal.SIGINT, signal.SIGTERM):
            self.handlers[number] = signal.getsignal(number)
            signal.signal(number, self._handler)

    def _pins(self, frame, deadline):
        for row in [frame['python'], *frame['raw_source']]:
            if self.now() >= deadline or not 0 <= row['bytes'] <= 32 * 1024**2:
                raise Refusal('PIN_DEADLINE_OR_BOUND')
            fd = os.open(row['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != row['mode'] or before.st_size != row['bytes']:
                    raise Refusal('PIN_FILE_SHAPE')
                digest = hashlib.sha256()
                remaining = row['bytes']
                while remaining:
                    if self.now() >= deadline:
                        raise Refusal('PIN_DEADLINE')
                    part = os.read(fd, min(65536, remaining))
                    if not part:
                        raise Refusal('PIN_SHORT_READ')
                    digest.update(part)
                    remaining -= len(part)
                after = os.fstat(fd)
                identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                if identity(before) != identity(after) or os.read(fd, 1) or digest.hexdigest() != row['sha256']:
                    raise Refusal('PIN_CHANGED')
            finally:
                os.close(fd)

    def postflight(self, frame, deadline):
        self._pins(frame, deadline)

    def birth(self, frame):
        if not self.sigchld_established:
            raise Refusal('WAITABLE_CHILD_PREREQUISITE_MISSING')
        self.birth_started = True
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        def child_setup():
            for number in (signal.SIGINT, signal.SIGTERM):
                signal.signal(number, signal.SIG_DFL)
            for kind, limit in ((resource.RLIMIT_CPU, 300), (resource.RLIMIT_AS, 1024**3), (resource.RLIMIT_FSIZE, 16 * 1024**2), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0)):
                resource.setrlimit(kind, (limit, limit))
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        try:
            self.process = subprocess.Popen(frame['argv'], cwd=frame['cwd'], env=frame['env'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True, preexec_fn=child_setup)
            LIVE[self.process.pid] = self.process
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        for slot, pipe in enumerate((self.process.stdout, self.process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            self.selector.register(pipe, selectors.EVENT_READ, slot)

    def has_child(self):
        return self.process is not None

    def _stat(self, pid):
        fd = os.open(f'/proc/{pid}/stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            return structural(os.read(fd, 4097), pid)
        finally:
            os.close(fd)

    def token(self, end):
        if self.process is None or self.now() >= end:
            raise Refusal('BIRTH_OWNERSHIP_UNKNOWN')
        self.peek((self.process.pid, None))
        self._action_guard(end)
        row = self._stat(self.process.pid)
        self._action_guard(end)
        if row[2:4] != (self.process.pid, self.process.pid):
            raise Refusal('PRIVATE_SESSION_NOT_ESTABLISHED')
        return (self.process.pid, row[5])

    def peek(self, token):
        if self.process is None or self.process.pid != token[0] or self.process.returncode is not None:
            raise Refusal('CHILD_OWNERSHIP_RELEASED')
        value = os.waitid(os.P_PID, token[0], os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if value is None:
            return None
        if value.si_pid != token[0]:
            raise Refusal('WAITID_CHILD_MISMATCH')
        if value.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
            raise Refusal('WAITID_TERMINAL_CODE')
        return value.si_status if value.si_code == os.CLD_EXITED else -value.si_status

    def members(self, token, end):
        rows = []
        count = 0
        with os.scandir('/proc') as entries:
            for entry in entries:
                count += 1
                if count > 8192 or self.now() >= end:
                    raise Refusal('PROC_SCAN_BOUND')
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                pid = int(entry.name)
                try:
                    row = self._stat(pid)
                except FileNotFoundError:
                    raise Refusal('PROC_VISIBILITY_INCOMPLETE')
                if row[0] == token[0] or row[2] == token[0] or row[3] == token[0]:
                    if len(rows) >= 256:
                        raise Refusal('GROUP_MEMBER_BOUND')
                    rows.append(row)
        return rows

    def _action_guard(self, end):
        # Checks are after potentially blocking observations and immediately
        # before the syscall. In-call kernel latency remains operational uncertainty.
        self.cancelled()
        now = self.now()
        if type(end) not in (int, float) or not math.isfinite(end) or not math.isfinite(now) or now >= end:
            raise Refusal('ADAPTER_ACTION_AFTER_ORIGINAL_END')

    def send_owned(self, token, kind, end):
        if kind not in ('TERM', 'KILL'):
            raise Refusal('OWNED_SIGNAL_KIND')
        terminal = self.peek(token)
        self._action_guard(end)
        disposition(terminal, [self._stat(token[0])], token)
        self._action_guard(end)
        os.killpg(token[0], signal.SIGTERM if kind == 'TERM' else signal.SIGKILL)

    def drain(self, remaining):
        read = 0
        for key, _ in self.selector.select(0):
            slot = key.data
            try:
                part = os.read(key.fd, min(65536, max(1, remaining - read + 1)))
            except BlockingIOError:
                continue
            if not part:
                self.selector.unregister(key.fileobj)
                continue
            read += len(part)
            if read > remaining:
                raise Refusal('OUTPUT_LIMIT')
            self.output[slot].extend(part)
        return read

    def eof(self):
        return not self.selector.get_map()

    def pause(self, seconds):
        time.sleep(max(0, seconds))

    def reap(self, token, expected, end):
        if self.peek(token) != expected or expected is None:
            raise Refusal('REAP_TERMINAL_MISMATCH')
        self._action_guard(end)
        if not disposition(expected, self.members(token, end), token):
            raise Refusal('ADAPTER_FINAL_GROUP_RESIDUE')
        self._action_guard(end)
        pid, status = os.waitpid(token[0], os.WNOHANG)
        if pid != token[0]:
            raise Refusal('REAP_RESULT_UNKNOWN')
        self.process.returncode = os.waitstatus_to_exitcode(status)
        LIVE.pop(token[0])
        if self.process.returncode != expected:
            raise Refusal('REAP_RESULT_MISMATCH')

    def close_capture(self):
        error = None
        try:
            self.selector.close()
        except BaseException as problem:
            error = problem
            if isinstance(problem, KeyboardInterrupt):
                self.cancel = self.cancel or 'KeyboardInterrupt'
        if self.process is not None:
            for pipe in (self.process.stdout, self.process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except BaseException as problem:
                        error = error or problem
                        if isinstance(problem, KeyboardInterrupt):
                            self.cancel = self.cancel or 'KeyboardInterrupt'
        if error is not None:
            raise error

    def release_handlers_after_publication(self):
        if self.birth_started and (self.process is None or self.process.returncode is None):
            raise Refusal('HANDLER_RESTORATION_DEFERRED_UNREAPED_OR_UNKNOWN_BIRTH')
        for number, handler in self.handlers.items():
            signal.signal(number, handler)


def execute_reserved(frame, nested_gate):
    # Root must derive entered/work_end/end from ORIGINAL_ENTRY once, or supply
    # explicitly reviewed original endpoints no later than ORIGINAL_ENTRY.
    if frame['entered'] > ORIGINAL_ENTRY:
        raise Refusal('CLOCK_RENEWAL')
    io = Linux()
    record = supervise(io, frame, nested_gate)
    record['sigchld_public_default_established'] = io.sigchld_established
    record['sigchld_original_retained'] = signal.SIGCHLD in io.handlers
    record['sigchld_C_flags_observed'] = False
    record['handler_restoration'] = 'ROOT_AFTER_PUBLICATION_AND_VERIFIED_REAP_OR_NO_BIRTH'
    return record, io
