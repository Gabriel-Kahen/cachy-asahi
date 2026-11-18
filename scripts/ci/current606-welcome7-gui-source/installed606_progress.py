# SPDX-License-Identifier: MIT
"""Bounded diagnostic-only transport for the existing installed606 verify command."""

SOURCE = '''
INSTALLED606_PHASES = (
    'inventory_begin', 'inventory_end', 'metadata_begin', 'metadata_end',
    'payload_begin', 'payload_progress', 'payload_end', 'recheck_begin', 'recheck_end',
)
INSTALLED606_PREFIX = b'INSTALLED606_OBSERVER_DATA '
INSTALLED606_ROW_CAP = 384
INSTALLED606_ROWS_CAP = 106


class Installed606Progress:
    def __init__(self):
        self.start = time.monotonic_ns()
        self.ordinal = 0

    def __call__(self, phase, nodes=0, payload_bytes=0, package_ordinal=0):
        if self.ordinal >= INSTALLED606_ROWS_CAP:
            return
        self.ordinal += 1
        row = dict(schema=1, phase=phase, ordinal=self.ordinal,
                   elapsed_ns=time.monotonic_ns() - self.start, nodes=nodes,
                   payload_bytes=payload_bytes, package_ordinal=package_ordinal)
        raw = INSTALLED606_PREFIX + json.dumps(row, separators=(',', ':'), sort_keys=True).encode() + b'\\n'
        if len(raw) <= INSTALLED606_ROW_CAP:
            try:
                os.write(2, raw)
            except OSError:
                pass  # Diagnostic loss must never change verification.


class Installed606ProgressForward:
    def __init__(self, send):
        self.send = send
        self.pending = bytearray()
        self.discard = False
        self.last = (-1, 0, 0, 0, 0, 0)

    def record(self, raw):
        if not raw.startswith(INSTALLED606_PREFIX):
            return
        try:
            row = json.loads(raw[len(INSTALLED606_PREFIX):])
            if type(row) is not dict or set(row) != {
                'schema', 'phase', 'ordinal', 'elapsed_ns', 'nodes', 'payload_bytes', 'package_ordinal',
            }:
                return
            phase = INSTALLED606_PHASES.index(row['phase'])
            values = tuple(row[field] for field in ('ordinal', 'elapsed_ns', 'nodes', 'payload_bytes', 'package_ordinal'))
            if type(row['schema']) is not int or row['schema'] != 1 or any(type(value) is not int for value in values):
                return
            if not all(low <= value <= high for value, low, high in zip(values, (1, 0, 0, 0, 0),
                       (INSTALLED606_ROWS_CAP, 600_000_000_000, 200_000, 6 * 1024**3, 606))):
                return
            prior, ordinal, *_ = self.last
            if values[0] <= ordinal or phase < prior or (phase == prior and row['phase'] != 'payload_progress'):
                return
            if any(value < previous for value, previous in zip(values[1:], self.last[2:])):
                return
            if raw != INSTALLED606_PREFIX + json.dumps(row, separators=(',', ':'), sort_keys=True).encode():
                return
            self.last = (phase, *values)
            self.send('installed606_observer_DATA', observer_stage=row.pop('phase'),
                      status='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE', **row)
        except Exception:
            return

    def feed(self, raw):
        for i, piece in enumerate(raw.split(b'\\n')):
            if i:
                if not self.discard:
                    self.record(bytes(self.pending))
                self.pending.clear()
                self.discard = False
            if not self.discard and len(self.pending) + len(piece) <= INSTALLED606_ROW_CAP:
                self.pending.extend(piece)
            else:
                self.discard = True
'''


VERIFY_ARGV = "['/usr/bin/python3','-I','-B',str(SHARE/'installed606.py'),'verify','/',str(SHARE/'alpm_reader.py'),str(SHARE/'expected.lock'),str(SHARE/'installed606.json')]"


def replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError('one exact installed606 progress seam required: ' + before[:80])
    return text.replace(before, after, 1)


def observer(text):
    insert = [
        ('def observe(root,helper,expected,*,deadline=600):',
         'def observe(root,helper,expected,*,deadline=600,report=None):'),
        ('    end=time.monotonic()+deadline;rows=helper.database(root,max_packages=606)',
         "    end=time.monotonic()+deadline\n    if report:report('inventory_begin')\n"
         "    rows=helper.database(root,max_packages=606)\n    if report:report('inventory_end')"),
        ('    initial_database=records()', "    if report:report('metadata_begin')\n    initial_database=records()\n    if report:report('metadata_end')"),
        ("    for row in rows:\n        need(row['name'] not in owners,",
         "    if report:report('payload_begin')\n    package_ordinal=0\n    for package_ordinal,row in enumerate(rows,1):\n        need(row['name'] not in owners,"),
        ("    links=[]", "            if report and len(nodes)%2048==0:report('payload_progress',len(nodes),total,package_ordinal)\n"
         "    if report:report('payload_end',len(nodes),total,package_ordinal)\n    links=[]"),
        ("    need(helper.database(root,max_packages=606)==rows", "    if report:report('recheck_begin',len(nodes),total,package_ordinal)\n    need(helper.database(root,max_packages=606)==rows"),
        ('    selected_prefixes=tuple(', "    if report:report('recheck_end',len(nodes),total,package_ordinal)\n    selected_prefixes=tuple("),
        ('    actual=observe(Path(root),load_db(Path(helper_path)),expected)',
         "    report=Installed606Progress() if mode=='verify' and root=='/' else None\n"
         "    actual=observe(Path(root),load_db(Path(helper_path)),expected,report=report)"),
        ("if __name__=='__main__':main()", SOURCE + "\nif __name__=='__main__':main()"),
    ]
    for before, after in insert:
        text = replace(text, before, after)
    return text


def guest(text):
    text = replace(text, 'class Logged:', SOURCE + '\n\nclass Logged:')
    text = replace(text, '        self.overflow = False\n',
                   '        self.overflow = False\n        self.forward = (Installed606ProgressForward(emit)\n'
                   "                        if name == 'installed606-preserved' and argv == " + VERIFY_ARGV + '\n'
                   '                        else None)\n')
    return replace(text, '                while raw := pipe.read(65536):\n',
                   "                forward = self.forward if path == self.paths[1] else None\n"
                   '                read = pipe.read1 if forward is not None else pipe.read\n'
                   '                while raw := read(65536):\n'
                   '                    if forward is not None:\n                        forward.feed(raw)\n')


def apply(output, pin):
    changes = {}
    for name, transform in (('installed606.py', observer), ('base_guest.py', guest)):
        path = output / name
        before = path.read_bytes()
        after = transform(before.decode()).encode()
        compile(after, str(path), 'exec')
        path.write_bytes(after)
        changes[name] = dict(before=pin(before), after=pin(after))
    return changes
