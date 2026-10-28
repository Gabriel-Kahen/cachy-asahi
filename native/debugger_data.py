# SPDX-License-Identifier: MIT
"""Passive debugger receipt/log checks; imports no actor or runner."""
import re
from common import need, pin, read, load

FLAGS = ['-Wall', '-Wextra', '-Werror', '-g', '-O0', '-fno-omit-frame-pointer']
RECORDS = [('initial-build', 'BUILT'), ('initial-debug', 'PASS_SOURCE_LOCAL_STACK_CONTINUE_EXIT'),
    ('edited-before-build', 'STALE_DEBUGGER_REFUSED'), ('edited-build', 'BUILT'),
    ('edited-debug', 'PASS_SOURCE_LOCAL_STACK_CONTINUE_EXIT'), ('broken-build', 'EXPECTED_COMPILE_FAILURE'),
    ('compile-failure-refusal', 'STALE_DEBUGGER_REFUSED'), ('restored-before-rebuild', 'STALE_DEBUGGER_REFUSED'),
    ('recovery-build', 'BUILT'), ('recovery-debug', 'PASS_SOURCE_LOCAL_STACK_CONTINUE_EXIT')]
COMMANDS = ['initial-build', 'initial-debug', 'edited-build', 'edited-debug',
            'broken-build', 'recovery-build', 'recovery-debug']
PREFIX = 'journey/debugger/'


def debugger_observation(raw, source, line, expected, version):
    text = raw.decode('utf-8', errors='replace')
    location = re.escape(source) + ':' + str(line)
    patterns = [r'(?m)^Breakpoint 1, workflow_step \(seed=10\) at ' + location + r'\r?$',
                r'(?m)^DEBUGGER_LOCAL:' + str(expected) + r'\r?$',
                r'(?m)^#0\s+workflow_step \(seed=10\) at ' + location + r'\r?$',
                r'(?m)^#1\s+(?:0x[0-9a-f]+ in )?main \(\) at ' + re.escape(source) + r':\d+\r?$',
                r'(?m)^Debugger version ' + version + ': ' + str(expected) + r'\r?$',
                r'(?m)^\[Inferior \d+ \(process \d+\) exited normally\]\r?$',
                r'(?m)^DEBUGGER_EXIT:0\r?$', r'(?m)^DEBUGGER_DONE\r?$']
    end = 0
    for pattern in patterns:
        matches = list(re.finditer(pattern, text))
        need(len(matches) == 1 and matches[0].start() >= end, 'raw GDB missing/duplicate/out-of-order observation')
        end = matches[0].end()
    return dict(source_breakpoint=dict(path=source, line=line), known_local=expected,
                stack=['workflow_step(seed=10)', 'main()'], continued=True, normal_exit=0)


def script_bytes(source, binary, line):
    def quote(value):
        need(not any(c in value for c in ('\n', '\r', '\0')), 'GDB DATA path')
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    return ('set pagination off\nset confirm off\nset startup-with-shell off\n'
            'set disable-randomization off\nset print frame-arguments all\n'
            'file ' + quote(binary) + '\n'
            'break ' + quote(source) + ':' + str(line) + '\n'
            'run\nprintf "DEBUGGER_LOCAL:%d\\n", known_local\n'
            'backtrace 4\ncontinue\nprintf "DEBUGGER_EXIT:%d\\n", $_exitcode\n'
            'echo DEBUGGER_DONE\\n\n').encode()


def validate_feature(view, feature, source_root):
    def raw(name):
        relative = PREFIX + name
        need(relative in view.entries and view.entries[relative]['kind'] == 'file', 'ordinary debugger artifact required')
        return view.read(relative)
    need(feature == view.load(PREFIX + 'result.json') and feature['status'] == 'PASS_LOCAL_DEBUGGER_COMPONENT'
         and feature['architecture'] == 'aarch64' and feature['uid'] != 0
         and set(feature['projects']) == {'c', 'cpp'} and set(feature['tools']) == {'cc', 'c++', 'gdb'},
         'actual native C/C++ debugger feature')
    source_map = load(source_root / 'native/source-map.json')['files']
    for key, name in [('runner', 'scripts/workflows/developer_debugger.py'),
                      ('helper', 'scripts/workflows/developer_workflow.py'),
                      ('owned_process', 'scripts/virtual/owned_process.py')]:
        need(feature['sources'][key] == {k:source_map[name][k] for k in ('bytes','sha256')}, 'pinned feature source receipt')
    need(feature['sources']['fixtures'] == {n: pin(read(source_root / 'tests/workflows/fixtures/debugger' / n))
         for n in ('hello.c','hello.cpp','LICENSE')}, 'original MIT fixture pins')
    commands = feature['commands']
    need(commands == view.load(PREFIX+'commands.json'), 'complete independent command receipt')
    steps = ['version-cc','version-cpp','version-gdb'] + [language+'-'+step for language in ('c','cpp') for step in COMMANDS]
    need([r['step'] for r in commands] == steps, 'exact17 commands; no debugger launches on stale refusals')
    logs = {}
    for number, row in enumerate(commands):
        need(row['log'] == '%03d-%s.log' % (number,row['step']), 'exact ordered raw log name')
        body = raw(row['log']); logs[row['step']] = body
        need(pin(body) == row['log_pin'] and row['success'] is True, 'real feature raw log pin')
        state = row['supervision']; expected = 'nonzero' if row['step'].endswith('broken-build') else 0
        need(row['expected'] == expected and state['reaped'] is True and state['ownership'] == 'REAPED'
             and state['group_census'] == 'EMPTY_TWICE' and state['output_complete'] is True
             and state['error'] is None and state['timeout'] is False and not state['signals']
             and (type(state['exit']) is int and state['exit'] > 0 if expected == 'nonzero' else state['exit'] == 0),
             'direct owned feature wait and expected command outcome')
    for tool in ('cc','c++','gdb'):
        value=feature['tools'][tool]; step='version-'+tool.replace('+','p')
        need(value['status']=='PRESENT' and value['resolved'].startswith('/usr/bin/'), 'selected ALARM tool path')
        need(value['version']==logs[step].decode(errors='replace').splitlines()
             and next(r for r in commands if r['step']==step)['argv']==[value['resolved'],'--version'], 'raw tool version receipt')
    need(re.search(rb'(?m)^GNU gdb .*\b18\.1\b', logs['version-gdb']) is not None, 'actual pinned GDB18.1 version')
    for language in ('c','cpp'):
        validate_project(view, feature, language, raw, logs, source_root)
    return dict(status='VALIDATED_REAL_GDB_17_THEN21_FAILURE_REFUSAL_REPAIR', languages=['c','cpp'], commands=17)


def validate_project(view, feature, language, raw, logs, source_root):
    project=feature['projects'][language]
    need(project==view.load(PREFIX+'project-'+language+'.json')
         and project['status']=='PASS_REAL_GDB_WORKFLOW' and project['language']==language
         and project['compile_failure']=='REAL_NONZERO_STALE_DEBUGGER_REFUSED'
         and project['recovery']=='PASS_REBUILT', 'real project journey receipt')
    records=project['records']
    need([(r['step'],r['outcome']) for r in records]==RECORDS, 'all ten ordered project transitions')
    original=read(source_root/'tests/workflows/fixtures/debugger'/('hello.'+language))
    edited=original.replace(b'seed + 7',b'seed + 11').replace(b'version one',b'version two').replace(b'== 17',b'== 21')
    broken=edited+b'\n#error INTENTIONAL_DEBUGGER_COMPILE_FAILURE\n'
    snapshots=[original,original,edited,edited,edited,broken,broken,edited,edited,edited]
    source='/out/'+PREFIX+language+'-project/hello.'+language
    binary='/out/'+PREFIX+language+'-project/hello'
    compiler=feature['tools']['cc' if language=='c' else 'c++']; debugger=feature['tools']['gdb']
    commands=feature['commands']
    for number,(row,body) in enumerate(zip(records,snapshots)):
        snapshot='source-%s-%02d.%s' % (language,number,language)
        need(row['source_snapshot']==snapshot and raw(snapshot)==body
             and row['source_snapshot_pin']==pin(body), 'original/edited/failed/repaired source bytes')
        need(row['inputs']==dict(source=pin(body),compiler=compiler['file'],debugger=debugger['file'],flags=FLAGS), 'bound source/tool/flag identity')
        if row['outcome']=='STALE_DEBUGGER_REFUSED':
            need(row['attempted_launches']==0, 'stale debugger must refuse before launch')
        if row['outcome'] in ('BUILT','EXPECTED_COMPILE_FAILURE'):
            command=next(r for r in commands if r['step']==language+'-'+row['step'])
            need(command['argv']==[compiler['resolved'],*FLAGS,source,'-o',binary], 'direct selected compiler argv')
        if row['outcome']=='PASS_SOURCE_LOCAL_STACK_CONTINUE_EXIT':
            expected,version=(17,'one') if row['step']=='initial-debug' else (21,'two')
            line=next(n for n,s in enumerate(body.decode().splitlines(),1) if '/* WORKFLOW_BREAKPOINT */' in s)
            script=language+'-'+row['step']+'.gdb'; script_path='/out/'+PREFIX+script
            need(raw(script)==script_bytes(source,binary,line)
                 and row['debugger_commands']==dict(path=script_path,file=pin(raw(script))), 'exact GDB child-only command script')
            need(row['observed']==debugger_observation(logs[language+'-'+row['step']],source,line,expected,version)
                 and row['binding']==dict(inputs=row['inputs'],binary=row['binary']), 'raw GDB observations and build binding')
            command=next(r for r in commands if r['step']==language+'-'+row['step'])
            need(command['argv']==[debugger['resolved'],'-nx','-nh','--quiet','--batch',
                '-iex','set auto-load off','-iex','set debuginfod enabled off','-x',script_path], 'isolated GDB argv')
    need(records[0]['binary']==records[1]['binary']==records[2]['binary']
         and records[3]['binary']==records[4]['binary']==records[5]['binary']==records[6]['binary']==records[7]['binary']
         and records[5]['previous_binary']==records[4]['binary']
         and records[8]['binary']==records[9]['binary'] and records[0]['binary']!=records[3]['binary'],
         'stale products retained/refused and actual edited binary identity')
    need(project['initial']==dict(inputs=records[0]['inputs'],binary=records[0]['binary'])
         and project['edited']==dict(inputs=records[3]['inputs'],binary=records[3]['binary']), 'initial and edited build identities')
    need(pin(raw(language+'-project/hello'))==records[9]['binary']
         and raw(language+'-project/hello.'+language)==edited, 'actual final repaired product and source retained')
    need(b'INTENTIONAL_DEBUGGER_COMPILE_FAILURE' in logs[language+'-broken-build'], 'real deliberate compiler diagnostic')
