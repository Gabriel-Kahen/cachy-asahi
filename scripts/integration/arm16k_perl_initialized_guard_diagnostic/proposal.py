# SPDX-License-Identifier: MIT
"""Exact Source310 two-leaf diagnostic transform; no policy or actor changes."""
import hashlib
import re

PINS = {'guest/root.sh': (19694, '34e0134604fe6ddb1804f2fb3eb65feda2d99e7181488c77497830b37bfc87e9'),
        'guest/initialized-state.sh': (6087, '164ad16f5b3dc732ad9a3d26b027b1b135f5a4f09fcd46961676328929b7095c')}
RETURN = re.compile(r'\breturn(?: (2))?\b')
STAGES = ('METADATA_RETURNED', 'COPY_DONE', 'REMOVE_DONE', 'ASSERT_USERS_ENTER',
          'ASSERT_USERS_DONE', 'USER_DIR_DONE', 'INSTALLED_MARKER_DONE',
          'SNAPSHOT_ENTER', 'SNAPSHOT_GUARD1_DONE', 'SNAPSHOT_META_DONE',
          'SNAPSHOT_GUARD2_DONE', 'SNAPSHOT_XATTR_DONE', 'SNAPSHOT_GUARD3_DONE',
          'SNAPSHOT_HASH_DONE', 'USERS_SNAPSHOT_DONE', 'USERS_META_MATCHED',
          'USERS_HASH_MATCHED', 'USERS_XATTR_MATCHED')

def need(ok, why):
    if not ok: raise ValueError(why)

def exact(raw, name):
    need((len(raw), hashlib.sha256(raw).hexdigest()) == PINS[name], 'exact Source310 predecessor: ' + name)

def replace(raw, before, after):
    need(raw.count(before) == 1, 'exact single diagnostic seam')
    return raw.replace(before, after)

def transform(files):
    need(set(files) == set(PINS), 'only exact two initialized guest leaves')
    for name, raw in files.items(): exact(raw, name)
    rows = []; body = []; function = None
    for line_number, line in enumerate(files['guest/initialized-state.sh'].decode().splitlines(keepends=True), 1):
        header = re.match(r'^([a-z_][a-z_0-9]*)\(\)', line)
        if header: function = header[1]
        def observe(match):
            code = 'R' + str(len(rows) + 1)
            index = '13' if function == '_initialized_empty' else '${i:-14}'
            explicit = match.group(1)
            rows.append(dict(check=code, function=function, line=line_number, original=line.rstrip('\n'),
                             return_code=2 if explicit else 'UNCHANGED', index=index))
            if explicit: return '{ _ig_diagnostic ' + code + ' "' + index + '";return 2; }'
            return ('{ local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic ' +
                    code + ' "' + index + '";fi;return "$_ig_diagnostic_rc"; }')
        body.append(RETURN.sub(observe, line))
    guarded = ''.join(body)
    implicit = {
        'I0': ('_initialized_identity() { stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$1"; }',
               '_initialized_identity() { stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$1" || { local _ig_diagnostic_rc=$?;_ig_diagnostic I0 "${i:-14}";return "$_ig_diagnostic_rc"; }; }'),
        'E0': (' [[ -z $found && $(_initialized_identity "$path") == "$before" ]]',
               ' [[ -z $found && $(_initialized_identity "$path") == "$before" ]] || { _ig_diagnostic E0 13;return 1; }')}
    for before, after in implicit.values(): guarded = replace(guarded, before, after)
    prefix = '''# SPDX-License-Identifier: MIT
# Public fixed check/index and substage observations only, outside all frames.
_ig_diagnostic() {
 [[ $# == 2 ]] || return 0
 case "$1" in CODES) :;;*) return 0;;esac
 case "$2" in 0|1|2|3|4|5|6|7|8|9|10|11|12|13|14) :;;*) return 0;;esac
 { builtin printf '\\nPERL5423_INITIALIZED_GUARD_DIAGNOSTIC_V1 CHECK=%s INDEX=%s\\n' "$1" "$2" >> /dev/ttyAMA0; } 2>/dev/null || :
 return 0
}
_ig_substage() {
 [[ $# == 1 ]] || return 0
 case "$1" in STAGES) :;;*) return 0;;esac
 { builtin printf '\\nPERL5423_POST_METADATA_DIAGNOSTIC_V1 STAGE=%s\\n' "$1" >> /dev/ttyAMA0; } 2>/dev/null || :
 return 0
}
'''.replace('CODES', '|'.join(['I0','E0'] + [r['check'] for r in rows])).replace('STAGES', '|'.join(STAGES))
    old_root = files['guest/root.sh'].decode(); root = old_root
    seams = [
        ('verify_installed_metadata "$D" "$O/installed-metadata"\n', 'METADATA_RETURNED'),
        ('cp -- "$O/installed-metadata/added.paths" "$S/added.paths"\n', 'COPY_DONE'),
        ('rm -r -- "$O/installed-metadata"\n', 'REMOVE_DONE'),
        ('assert_users\ninstall -d -m700 -o1000 -g1000 "$O/user"\n',
         'ASSERT_USERS_DONE'),
        ('printf \'%s\\n\' "$nonce" > "$O/installed";chmod 644 "$O/installed"\n', 'INSTALLED_MARKER_DONE'),
        (' ulimit -f 16384\n root_ssh_guard\n', 'SNAPSHOT_ENTER'),
        (' user_snapshot "$S/user-current"\n', 'USERS_SNAPSHOT_DONE'),
        (' same_bytes "$S/user-before.meta" "$S/user-current.meta"\n', 'USERS_META_MATCHED'),
        (' same_bytes "$S/user-before.hash" "$S/user-current.hash"\n', 'USERS_HASH_MATCHED'),
        (' same_bytes "$S/user-before.xattr" "$S/user-current.xattr"\n', 'USERS_XATTR_MATCHED')]
    for before, stage in seams:
        if stage == 'ASSERT_USERS_DONE':
            after = '_ig_substage ASSERT_USERS_ENTER\nassert_users\n_ig_substage ASSERT_USERS_DONE\ninstall -d -m700 -o1000 -g1000 "$O/user"\n_ig_substage USER_DIR_DONE\n'
        elif stage == 'SNAPSHOT_ENTER':
            after = ' _ig_substage SNAPSHOT_ENTER\n ulimit -f 16384\n root_ssh_guard\n _ig_substage SNAPSHOT_GUARD1_DONE\n'
        else: after = before + (' ' if before.startswith(' ') else '') + '_ig_substage ' + stage + '\n'
        root = replace(root, before, after)
    snapshot_start = root.index('user_snapshot() (')
    snapshot_end = root.index('assert_users() {', snapshot_start)
    snapshot = root[snapshot_start:snapshot_end]
    lines = snapshot.splitlines(keepends=True); observed = []; find_count = 0; guard_count = 1
    for line in lines:
        observed.append(line)
        if line.startswith(' find '):
            find_count += 1
            observed.append(' _ig_substage ' + {1:'SNAPSHOT_META_DONE',2:'SNAPSHOT_XATTR_DONE',3:'SNAPSHOT_HASH_DONE'}[find_count] + '\n')
        elif line == ' root_ssh_guard\n' and find_count:
            guard_count += 1; observed.append(' _ig_substage SNAPSHOT_GUARD' + str(guard_count) + '_DONE\n')
    need(find_count == 3 and guard_count == 3, 'exact original three private-pruned snapshot boundaries')
    root = root[:snapshot_start] + ''.join(observed) + root[snapshot_end:]
    # Every Root change is a fixed observation line. No command or test is changed.
    need(re.sub(r'^ *_ig_substage [A-Z0-9_]+\n', '', root, flags=re.M) == old_root, 'complete Root command/predicate inverse')
    generated = {'guest/root.sh': root.encode(), 'guest/initialized-state.sh': (prefix + guarded).encode()}
    mapping = dict(predecessors={k:dict(bytes=v[0],sha256=v[1])for k,v in PINS.items()},
                   returns=rows, implicit={k:dict(before=v[0],after=v[1])for k,v in implicit.items()},
                   public_nodes=re.search(r'^initialized_paths=\(([^)]+)\)$', files['guest/initialized-state.sh'].decode(), re.M)[1].split(),
                   stages=list(STAGES), index_scope='0..13 existing initialized_paths order;14 descriptor/context or unset',
                   actual=dict(predicate_cause=None,Root_source=None,VM=None,M2=None,release=None))
    return generated, mapping

def inverse(files, generated, mapping):
    expected, table = transform(files)
    need(generated == expected and mapping == table, 'exact two-leaf diagnostic-only projection')
    return files
