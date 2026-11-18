# SPDX-License-Identifier: MIT
"""Initialize staged system users and retain bounded installed606 diagnostics."""

TCG_OBSERVE_SECONDS = 720
TCG_VERIFY_SECONDS = 735

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


DIFFERENCE = r"""
import hashlib
import re

INSTALLED606_DIFF_PREFIX = b'INSTALLED606_DIFFERENCE_DATA '
INSTALLED606_DIFF_ROW_CAP = 768
INSTALLED606_DIFF_LIMIT = 2
INSTALLED606_DIFF_SECTIONS = (
    'schema_version', 'packages', 'ownership', 'nodes', 'hardlinks',
    'nonselected_database', 'capabilities', 'payload_bytes', 'qualification', 'other',
)
INSTALLED606_DIFF_FIELDS = dict(bytes='size', gid='gid', mode='mode', sha256='content',
                                target='link_target', type='type', uid='uid')
INSTALLED606_DIFF_DB_ROLES = ('desc', 'files', 'install', 'mtree')


def installed606_diff_wire(row):
    return INSTALLED606_DIFF_PREFIX + json.dumps(row, separators=(',', ':'), sort_keys=True).encode()


def installed606_diff_sample(section, key, old, new, change, expected):
    if section in ('packages', 'ownership'):
        if key not in expected:
            return None
        kind, token = 'package', key
    else:
        kind = 'hardlink_group_sha256' if section == 'hardlinks' else 'path_sha256'
        token = hashlib.sha256(json.dumps(key, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    sample = dict(change=change, kind=kind, token=token)
    if section == 'nodes' and change == 'changed' and type(old) is dict and type(new) is dict:
        fields = {INSTALLED606_DIFF_FIELDS.get(name, 'other')
                  for name in old.keys() | new.keys()
                  if name not in old or name not in new or old[name] != new[name]}
        sample['fields'] = sorted(fields)
    if section == 'nonselected_database':
        role = key.rpartition('/')[2]
        if role in INSTALLED606_DIFF_DB_ROLES:
            sample['record'] = role
    return sample


def installed606_diff_rows(actual, baseline, expected):
    for section in INSTALLED606_DIFF_SECTIONS:
        old = baseline.get(section)
        new = actual.get(section)
        if section == 'other':
            old = {k: v for k, v in baseline.items() if k not in INSTALLED606_DIFF_SECTIONS[:-1]}
            new = {k: v for k, v in actual.items() if k not in INSTALLED606_DIFF_SECTIONS[:-1]}
        if old == new and (section == 'other' or (section in actual) == (section in baseline)):
            continue
        summary = dict(schema=1, section=section, counts=dict(added=0, removed=0, changed=0), samples=[])
        if section == 'hardlinks' and type(old) is list and type(new) is list:
            if all(type(group) is list and all(type(path) is str for path in group) for group in old + new):
                old = dict.fromkeys(map(tuple, old))
                new = dict.fromkeys(map(tuple, new))
        detailed = section not in ('schema_version', 'payload_bytes', 'qualification', 'other')
        if detailed and type(old) is dict and type(new) is dict:
            for key in sorted(old.keys() | new.keys()):
                if key not in old:
                    change = 'added'
                elif key not in new:
                    change = 'removed'
                elif old[key] != new[key]:
                    change = 'changed'
                else:
                    continue
                summary['counts'][change] += 1
                if len(summary['samples']) < INSTALLED606_DIFF_LIMIT:
                    sample = installed606_diff_sample(section, key, old.get(key), new.get(key), change, expected)
                    if sample is not None:
                        summary['samples'].append(sample)
        if not any(summary['counts'].values()):
            summary['counts']['changed'] = 1
        yield summary


def installed606_emit_diff(actual, baseline, expected):
    rows = installed606_diff_rows(actual, baseline, expected) if type(baseline) is dict else (
        dict(schema=1, section='other', counts=dict(added=0, removed=0, changed=1), samples=[]),)
    for row in rows:
        raw = installed606_diff_wire(row)
        if len(raw) <= INSTALLED606_DIFF_ROW_CAP:
            os.write(2, raw + b'\n')


def installed606_read_diff(raw):
    if len(raw) > INSTALLED606_DIFF_ROW_CAP:
        return None
    row = json.loads(raw[len(INSTALLED606_DIFF_PREFIX):])
    if (type(row) is not dict or set(row) != {'schema', 'section', 'counts', 'samples'}
            or type(row['schema']) is not int or row['schema'] != 1
            or row['section'] not in INSTALLED606_DIFF_SECTIONS or raw != installed606_diff_wire(row)):
        return None
    section, counts, samples = row['section'], row['counts'], row['samples']
    if (type(counts) is not dict or set(counts) != {'added', 'removed', 'changed'}
            or any(type(v) is not int or not 0 <= v <= 200_000 for v in counts.values())
            or not any(counts.values()) or type(samples) is not list or len(samples) > INSTALLED606_DIFF_LIMIT):
        return None
    kind = {
        'packages': 'package', 'ownership': 'package', 'hardlinks': 'hardlink_group_sha256',
        'nodes': 'path_sha256', 'nonselected_database': 'path_sha256', 'capabilities': 'path_sha256',
    }.get(section)
    seen = set()
    sampled = dict.fromkeys(counts, 0)
    for sample in samples:
        if type(sample) is not dict or kind is None:
            return None
        names = set(sample)
        basic = {'change', 'kind', 'token'}
        if (not basic <= names or not names <= basic | {'fields', 'record'}
                or sample['kind'] != kind or type(sample['change']) is not str
                or sample['change'] not in counts or type(sample['token']) is not str):
            return None
        token = sample['token']
        pattern = r'[a-z0-9@_+.-]{1,128}' if kind == 'package' else r'[0-9a-f]{64}'
        if re.fullmatch(pattern, token) is None or token in seen:
            return None
        seen.add(token)
        sampled[sample['change']] += 1
        if 'fields' in sample:
            fields = sample['fields']
            if (section != 'nodes' or sample['change'] != 'changed' or type(fields) is not list
                    or not 0 < len(fields) <= 8 or any(type(f) is not str for f in fields)
                    or fields != sorted(set(fields))
                    or set(fields) - set(INSTALLED606_DIFF_FIELDS.values()) - {'other'}):
                return None
        if 'record' in sample and (section != 'nonselected_database' or sample['record'] not in INSTALLED606_DIFF_DB_ROLES):
            return None
    return row if all(sampled[k] <= counts[k] for k in counts) else None
"""


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


def tcg_verify_capacity(name, text):
    if name == 'installed606.py':
        text = replace(text, 'expected,report=report)',
                       f'expected,deadline={TCG_OBSERVE_SECONDS} if report is not None else 600,report=report)')
    else:
        command = "proof=command(" + VERIFY_ARGV + ",env,logs,'installed606-preserved',timeout="
        text = replace(text, command + '600)', command + f'{TCG_VERIFY_SECONDS})')
    return replace(text, '600_000_000_000', f'{TCG_OBSERVE_SECONDS * 10**9:_}')


def tcg_compare_diagnostics(name, text):
    if name == 'installed606.py':
        text = replace(text, "def verify(actual,baseline):\n    need(actual==baseline,",
            "def verify(actual,baseline,report_difference=None):\n"
            "    same=actual==baseline\n"
            "    if not same and report_difference is not None:\n"
            "        try:report_difference(actual,baseline)\n"
            "        except Exception:pass  # Diagnostics cannot change the strict compare result.\n"
            "    need(same,")
        text = replace(text, '    else:verify(actual,read(snapshot))',
            '    else:verify(actual,read(snapshot),\n'
            "                (lambda now,before:installed606_emit_diff(now,before,expected)) if report is not None else None)")
        return replace(text, "if __name__=='__main__':main()", DIFFERENCE + "\nif __name__=='__main__':main()")
    text = replace(text, 'class Logged:', DIFFERENCE + '\n\nclass Logged:')
    text = replace(text, '        self.last = (-1, 0, 0, 0, 0, 0)\n',
                   '        self.last = (-1, 0, 0, 0, 0, 0)\n        self.last_diff = -1\n')
    text = replace(text, '    def record(self, raw):\n',
        '    def record(self, raw):\n'
        '        if raw.startswith(INSTALLED606_DIFF_PREFIX):\n'
        '            if self.last[0] == len(INSTALLED606_PHASES) - 1:\n'
        '                try:\n'
        '                    row = installed606_read_diff(raw)\n'
        '                    if row is not None:\n'
        "                        index = INSTALLED606_DIFF_SECTIONS.index(row['section'])\n"
        '                        if index > self.last_diff:\n'
        '                            self.last_diff = index\n'
        "                            self.send('installed606_difference_DATA', status='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE', **row)\n"
        '                except Exception:\n'
        '                    pass\n'
        '            return\n'
        '        if len(raw) > INSTALLED606_ROW_CAP:\n'
        '            return\n')
    return replace(text, 'len(piece) <= INSTALLED606_ROW_CAP:',
                   'len(piece) <= INSTALLED606_DIFF_ROW_CAP:')


def staged_system_users(text):
    anchor = "python3 -I -B /runner/installed606.py capture "
    prepare = """# Match the boot sysusers service in the disposable root before measuring its payload.
[[ "$root" == /out/staged && -d "$root" && ! -L "$root" ]]
/usr/bin/cmp --silent -- /usr/bin/systemd-sysusers "$root/usr/bin/systemd-sysusers"
/usr/bin/timeout --signal=TERM --kill-after=3s 15s /usr/bin/systemd-sysusers --root="$root" >/dev/null 2>&1 || {
  printf '%s\\n' 'staged systemd-sysusers failed before installed606 capture' >&2
  exit 1
}
printf '%s\\n' 'staged systemd-sysusers completed before installed606 capture'
"""
    return replace(text, anchor, prepare + anchor)


def apply(output, pin, *, mode):
    if mode not in ('generic4k', 'generic16k'):
        raise ValueError('exact supported installed606 mode required')
    changes = {}
    for name, transform in (('installed606.py', observer), ('base_guest.py', guest)):
        path = output / name
        before = path.read_bytes()
        after = transform(before.decode())
        if mode == 'generic16k':
            after = tcg_compare_diagnostics(name, tcg_verify_capacity(name, after))
        after = after.encode()
        compile(after, str(path), 'exec')
        path.write_bytes(after)
        changes[name] = dict(before=pin(before), after=pin(after))
    if mode == 'generic16k':
        path = output / 'desktop574_fixture.sh'
        before = path.read_bytes()
        after = staged_system_users(before.decode()).encode()
        path.write_bytes(after)
        changes[path.name] = dict(before=pin(before), after=pin(after))
    return changes
