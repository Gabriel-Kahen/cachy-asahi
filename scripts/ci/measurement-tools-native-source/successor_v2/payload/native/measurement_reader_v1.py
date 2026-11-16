# SPDX-License-Identifier: MIT
"""Strict passive Measurement DATA reader. Capsule content is never executed."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import consumer_contract,load,need,pin,read,verify_source
from capsule import open_capsule
# These helpers are unchanged in the genuine191 source closure; all imports are passive.
from reader import (retained_failure_data,retained_image_lifecycle,
 retained_consumer_diagnostic,retained_safe_diagnostic,retained_transport_diagnostic,
 retained_transport_proof)
import measurement_tools_v1 as T
PRODUCERS={}
PASS='PASS_MEASUREMENT_TOOLS_NATIVE_ALPM_COMPONENT'
OPERATION='measurement-tools-alpm-v1'
ABSENCE_OUTPUT=b'gpg-connect-agent: no gpg-agent running in this session\n'


def measurement_contract():
    root=Path(__file__).resolve().parents[1]
    value,_=T.source_policy(root)
    need(pin(read(root/'native/measurement-contract-v1.json'))['sha256']==PRODUCERS['native/measurement-contract-v1.json'],
         'complete-source-map-bound Measurement contract')
    return value


def measurement_archive_custody(raw, command, contract, index, private_marker):
    """Independently parse exact public source bodies and every tar byte boundary."""
    import io
    import tarfile
    need(type(raw) is bytes and 0<len(raw)<=2*1024**2 and len(raw)%512==0,
         'bounded block-aligned package tar required')
    label={'archive-a':'a','archive-b':'b'}.get(command.get('step'))
    recipe=contract['recipe'];fixed=Path(contract['invocation']['source']).parent
    need(label is not None and type(index) is int and index>=0
         and command.get('log')=='%03d-archive-%s.log'%(index,label)
         and command.get('argv')==['/usr/bin/zstd','-dc',str(fixed/'build-inputs'/label/recipe['archive'])]
         and type(command.get('expected')) is int and command['expected']==0
         and command.get('log_pin')==pin(raw), 'exact source-owned archive decoder command and raw pin required')
    expected=recipe['payload_files'];need(len(expected)==14,'exact14 source-bound package payload required')
    ancestors={str(parent) for leaf in expected for parent in Path(leaf).parents if str(parent)!='.'}
    payload={};metadata={};seen=set();directories=set();cursor=0;headers=0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
            for member in archive:
                name=member.name.rstrip('/')
                need(member.offset==cursor and member.offset_data==cursor+512 and not member.pax_headers
                     and member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE),
                     'contiguous single-header ordinary tar member required; hidden headers refused')
                header=raw[cursor:cursor+512]
                need(len(header)==512 and not private_marker.search(header),'private marker in package tar header refused')
                need(name not in seen and member.uid==member.gid==0 and name==Path(name).as_posix()
                     and '..' not in Path(name).parts,'unique canonical root-owned package members required')
                need(type(member.size) is int and 0<=member.size<=1024**2,'finite nonnegative package member size required')
                seen.add(name);start=member.offset_data;end=start+member.size;padded=start+((member.size+511)//512)*512
                need(end<=padded<=len(raw) and not any(raw[end:padded]),'package tar padding must be zero')
                if member.isdir():
                    need(name in ancestors and member.mode==0o755 and member.size==0,'exact zero-body package directory required')
                    directories.add(name)
                else:
                    need(member.isfile() and member.size<=1024**2,'ordinary finite package body required')
                    body=raw[start:end];need(len(body)==member.size,'complete raw package body required')
                    if name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                        need(member.mode==0o644 and not private_marker.search(body),'private marker or wrong mode in package metadata refused')
                        metadata[name]=body
                    else:
                        need(name in expected and member.mode==expected[name]['mode']
                             and pin(body)=={key:expected[name][key] for key in ('bytes','sha256')},'exact source-bound public package body required')
                        payload[name]=dict(mode=member.mode,**pin(body))
                cursor=padded;headers+=1
    except (tarfile.TarError,UnicodeError,EOFError):
        raise ValueError('bounded source-bound package tar structure refused') from None
    need(set(payload)==set(expected) and directories==ancestors and set(metadata)=={'.PKGINFO','.BUILDINFO','.MTREE'},
         'complete finite package payload and metadata namespace required')
    need(len(raw)-cursor>=1024 and not any(raw[cursor:]),'complete zero package tar trailer required')
    for name in ('.PKGINFO','.BUILDINFO'):
        need(len(metadata[name])<=256*1024,'bounded textual package metadata required')
    pkg=measurement_metadata(metadata['.PKGINFO']);build=measurement_metadata(metadata['.BUILDINFO'])
    need(all(re.fullmatch('[a-z][a-z0-9_]*',key) and all(len(value)<=8192 for value in values)
         for doc in (pkg,build) for key,values in doc.items()),'bounded canonical makepkg metadata fields required')
    for key,value in (('pkgname','cachy-asahi-measurement-tools'),('pkgbase','cachy-asahi-measurement-tools'),('pkgver','0.1.0-1'),('arch','any')):
        need(pkg.get(key)==[value],'exact package identity required')
    need(pkg.get('license')==['MIT'] and pkg.get('depend')==['python>=3.12']
         and pkg.get('checkdepend')==['bubblewrap'],'exact MIT package/runtime dependency metadata required')
    for key,value in (('format','2'),('pkgname','cachy-asahi-measurement-tools'),('pkgbase','cachy-asahi-measurement-tools'),
                      ('pkgver','0.1.0-1'),('pkgarch','any'),('pkgbuild_sha256sum',recipe['source_files']['PKGBUILD']['sha256'])):
        need(build.get(key)==[value],'exact package BUILDINFO identity required')
    installed=build.get('installed',[])
    need(len(installed)==len(set(installed))==349 and sorted(installed)==contract['buildinfo_installed']
         and 'check' in build.get('buildenv',[]) and '!check' not in build['buildenv'],'exact349 provenance and checks required')
    return dict(kind='exact-source-bound-measurement-package-tar-v1',label=label,step=command['step'],argv=command['argv'],
        raw_pin=pin(raw),contract_sha256=PRODUCERS['native/measurement-contract-v1.json'],payload_files=len(payload),
        metadata={name:pin(body) for name,body in metadata.items()},
        framing=dict(headers=headers,blocks=len(raw)//512,zero_padding=True,zero_trailer_bytes=len(raw)-cursor),
        privacy='Exact14 bound public payload bodies; every raw header and metadata body scanned; padding and trailer zero')


def retained_public_projection(view, files, binding, map_sha256):
    """Closed new component DATA seam; no original187 feature credit."""
    name = 'public-projection.json'
    need(name in files and files[name]['kind'] == 'file', 'source-owned finite projection receipt required')
    value = view.load(name)
    host = {'transport-diagnostic.json', 'transport-proof.json', 'receipt.json', 'cleanup.json', 'source-proof.json', 'consumer-inspect.json', 'consumer-after.json',
            'consumer-diagnostic.json', 'image-ledger.json', 'image-retirement.json', 'bootstrap-failure-retention.json',
            'provision-diagnostic.json', 'build-summary.json'}
    bootstrap = {phase + '-' + leaf for phase in ('bootstrap', 'overlay') for leaf in
                 ('packages.lock', 'signatures.json', 'bootstrap.json', 'cache-checksums.json', 'Dockerfile', 'runner.json')}
    bootstrap |= {'bootstrap-acquisition.json', 'bootstrap-key-import.log', 'bootstrap-bootstrap.log'}
    prefix = 'journey/measurement-tools-alpm-v1/'
    log_pattern = r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log'
    private_marker = re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b', re.I)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('status') == 'PASS_FINITE_MEASUREMENT_ALPM_PUBLIC_DATA_PROJECTION'
         and value.get('binding') == binding and value.get('source_map_sha256') == map_sha256
         and value.get('source_producers') == PRODUCERS
         and value.get('omitted_private_scopes') == ['journey/measurement-tools-alpm-v1/home']
         and value.get('original_output_unchanged') is True and value.get('omitted_private_trees_walked') is False
         and value.get('privacy') == 'Ordinary DATA marker refusal; only exact source-bound package tar custody permits bound public source identifiers'
         and value.get('scope') == 'Fixed measurement-tools-alpm-v1 result, commands and raw referenced logs only; private home trees not retained',
         'same-source exact finite release projection and explicit omission scope required')
    need(pin(view.read(name)) == {key: files[name][key] for key in ('bytes', 'sha256')}, 'projection receipt actual bytes differ')
    selected = value.get('selected')
    need(type(selected) is dict and 0 < len(selected) <= 2998 and set(files) == set(selected) | {name}
         and ('receipt.json' in selected) != ('provision-diagnostic.json' in selected),
         'closed finite projection leaf set and sole authority required')
    custody=value.get('archive_custody');need(type(custody) is dict and len(custody)<=2,'finite exact archive custody map required')
    result_name=prefix+'result.json';archive_commands={}
    if result_name in selected:
        source_report=view.load(result_name);source_commands=source_report.get('commands',[])
        need(type(source_commands) is list and len(source_commands)<=1000,'finite source command records required')
        for index,command in enumerate(source_commands):
            need(type(command) is dict,'typed original command row required')
            if command.get('step') in ('archive-a','archive-b'):
                leaf=command.get('log');need(type(leaf) is str and re.fullmatch(log_pattern,leaf),'exact archive log name required')
                target=prefix+leaf;need(target not in archive_commands,'duplicate archive custody target refused')
                archive_commands[target]=(index,command)
    checked_custody={}
    for target, row in selected.items():
        parts = target.split('/'); allowed = target in host or target in {'journey/result.json', 'journey/build-summary.json'}
        if len(parts) == 2:
            allowed |= (parts[0] == 'actor-logs' and re.fullmatch(r'[0-9]{4}\.log', parts[1]) is not None
                        or parts[0] == 'provision-logs' and re.fullmatch(r'(?:proof\.json|input-transport-owner\.json|input-cache-owner\.json)-[0-9]{3}\.log', parts[1]) is not None
                        or parts[0] == 'bootstrap-proof' and parts[1] in bootstrap
                        or parts[0] == 'transport-proof' and re.fullmatch(r'receipt\.json|[0-9]{4}\.(stdout|stderr)', parts[1]) is not None)
        if target.startswith(prefix):
            leaf = target[len(prefix):]
            allowed |= leaf in {'result.json', 'commands.json'} or re.fullmatch(log_pattern, leaf) is not None
        need(allowed and type(row) is dict and set(row) == {'kind', 'mode', 'source_mode', 'bytes', 'sha256'}
             and row['kind'] == 'file' and type(row['mode']) is int and row['mode'] == 0o600
             and type(row['source_mode']) is int and 0 <= row['source_mode'] <= 0o777
             and type(row['bytes']) is int and 0 <= row['bytes'] <= 16*1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'finite ordinary projected evidence leaf required')
        need(files[target] == {key: row[key] for key in ('kind', 'mode', 'bytes', 'sha256')}
             and pin(view.read(target)) == {key: row[key] for key in ('bytes', 'sha256')},
             'projection selected pin and modes must match manifest and actual DATA')
        if target in archive_commands:
            index,command=archive_commands[target]
            checked_custody[target]=measurement_archive_custody(view.read(target),command,measurement_contract(),index,private_marker)
        else:
            need(not private_marker.search(view.read(target)), 'private marker in projected public DATA refused')
    need(custody==checked_custody,'complete independently parsed source-bound archive custody required')
    result_name = prefix + 'result.json'
    actual_logs = {target for target in selected if target.startswith(prefix) and re.fullmatch(log_pattern, target[len(prefix):])}
    if result_name not in selected:
        need(not actual_logs, 'projected release logs require original component result')
        return dict(status='VALIDATED_FINITE_MEASUREMENT_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))
    report = view.load(result_name); commands = report.get('commands', [])
    need(type(commands) is list and len(commands) <= 1000, 'finite projected component command list required')
    wanted = set()
    for command in commands:
        leaf = command.get('log')
        need(type(leaf) is str and re.fullmatch(log_pattern, leaf) and prefix + leaf not in wanted,
             'finite unique projected release log names required')
        target = prefix + leaf; wanted.add(target)
        need(target in selected and {key: selected[target][key] for key in ('bytes', 'sha256')} == command.get('log_pin'),
             'all original release raw command logs must be projected')
    need(actual_logs == wanted, 'closed original release log projection required')
    command_file = prefix + 'commands.json'
    need(not commands or command_file in selected, 'actual component command list must be projected')
    if command_file in selected:
        need(view.load(command_file) == commands, 'projected standalone and release command lists differ')
    guest = view.load('journey/result.json') if 'journey/result.json' in selected else None
    if type(guest) is dict and guest.get('status') == PASS:
        need(guest.get('measurement_alpm') == report, 'positive guest and separately retained release results differ')
    return dict(status='VALIDATED_FINITE_MEASUREMENT_PUBLIC_DATA_PROJECTION_ONLY', selected=len(selected))




def strict_test_signature(status, signer):
    need(type(status) is str and len(status.encode()) <= 65536
         and re.fullmatch('[0-9A-F]{40}', signer or ''), 'bounded exact TEST signer status required')
    rows = [line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    forbidden = {'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'KEYEXPIRED',
                 'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'NODATA', 'TRUST_NEVER', 'TRUST_UNDEFINED'}
    need(not any(row and row[0] in forbidden for row in rows), 'bad/expired/revoked/unknown TEST signature refused')
    valid = [row for row in rows if row and row[0] == 'VALIDSIG']
    need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == signer,
         'exact TEST primary signer required')
    need(any(row and row[0] == 'TRUST_ULTIMATE' for row in rows), 'explicitly trusted TEST primary required')


def measurement_commands(view, files, prefix, commands):
    need(type(commands) is list and 0 < len(commands) <= 240 and view.load(prefix + 'commands.json') == commands,
         'actual finite standalone Measurement command list required')
    for index, command in enumerate(commands):
        need(type(command) is dict, 'typed Measurement command row required')
        step = command.get('step'); log = command.get('log'); state = command.get('supervision')
        need(type(step) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}', step)
             and log == '%03d-%s.log' % (index, step), 'ordered source-owned command log namespace required')
        target = prefix + log
        need(target in files and files[target]['kind'] == 'file'
             and pin(view.read(target)) == command.get('log_pin') == {k: files[target][k] for k in ('bytes', 'sha256')}, 'complete raw Measurement command log required')
        expected = command.get('expected'); code = state.get('exit') if type(state) is dict else None
        matched = type(code) is int and (code > 0 if expected == 'nonzero' else type(expected) is int and code == expected)
        need(command.get('success') is True and type(state) is dict and matched
             and state.get('reaped') is True and state.get('ownership') == 'REAPED'
             and state.get('group_census') == 'EMPTY_TWICE' and state.get('output_complete') is True
             and state.get('error') is None and state.get('timeout') is False and state.get('signals') == [], 'actual original owned natural retirement required')
        need(type(command.get('argv')) is list and 0 < len(command['argv']) <= 128
             and all(type(arg) is str and len(arg) <= 8192 for arg in command['argv']) and Path(command['argv'][0]).is_absolute(), 'bounded explicit platform argv required')
    def selected(step):
        rows = [(i, row) for i, row in enumerate(commands) if row['step'] == step]
        need(len(rows) == 1, 'sole exact Measurement command reference required')
        return rows[0]
    return selected


def measurement_metadata(raw):
    need(type(raw) is bytes and len(raw) <= 2*1024**2, 'bounded package metadata text required')
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'): continue
        need(' = ' in line, 'exact makepkg metadata separator required')
        key, value = line.split(' = ', 1); result.setdefault(key, []).append(value)
    return result


def measurement_build_pair(view, prefix, report, contract, selected, map_sha256):
    import io
    import tarfile
    recipe = contract['recipe']; builds = report.get('builds'); comparison = report.get('comparison')
    need(type(builds) is dict and set(builds) == {'a', 'b'} and type(comparison) is dict, 'two separate actual native builds/comparison required')
    need(comparison.get('status') == 'PASS_EXACT_NATIVE_BUILD_PAIR'
         and comparison.get('equality') == {key: True for key in ('archive', 'payload', 'pkginfo', 'buildinfo', 'mtree')}
         and comparison.get('source_map_sha256') == map_sha256 and comparison.get('payload_files') == 14
         and comparison.get('base_inventory_count') == 349
         and comparison.get('pkgbuild_sha256') == recipe['source_files']['PKGBUILD']['sha256'], 'exact native build-pair/provenance comparison required')
    expected = recipe['payload_files']; indexes = []; decoded = {}; archives = {}; identities = []
    fixed = Path(contract['invocation']['source']).parent; slot = fixed / 'build-current'
    for label in ('a', 'b'):
        build = builds[label]; archive = build.get('archive'); directory = build.get('build_directory')
        need(build.get('version') == '0.1.0-1' and build.get('recipe_sha256') == recipe['source_files']['PKGBUILD']['sha256']
             and build.get('check_invoked') is True and build.get('check_tests') == recipe['expected_test_counts'] == [8]
             and build.get('check_policy') == 'POSITIVE_CHECK_NO_NOCHECK', 'exact recipe and original positive8 makepkg checks required')
        need(type(directory) is dict and directory.get('logical') == str(slot) and directory.get('retained') == str(fixed/'build-inputs'/label)
             and directory.get('initial_files') == sorted(recipe['source_files']) and type(directory.get('identity')) is dict
             and set(directory['identity']) == {'device', 'inode'}
             and all(type(value) is int and value >= 0 for value in directory['identity'].values()), 'distinct fresh exact source directories required')
        identities.append(directory['identity'])
        need(type(archive) is dict and archive.get('filename') == recipe['archive'] and type(archive.get('bytes')) is int
             and 0 < archive['bytes'] <= 2*1024**2 and re.fullmatch('[0-9a-f]{64}', archive.get('sha256') or ''), 'bounded actual native archive pin required')
        archives[label] = {key: archive[key] for key in ('bytes', 'sha256')}
        index, command = selected(build.get('build_step')); indexes.append(index)
        argv = command['argv']; raw = view.read(prefix + command['log'])
        wanted = ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', 'HOME=' + str(slot),
                  'PKGDEST=' + str(slot), 'SRCDEST=' + str(slot), 'BUILDDIR=' + str(slot),
                  'SOURCE_DATE_EPOCH='+contract['build_pair']['source_date_epoch'], 'PACKAGER='+contract['build_pair']['packager'],
                  '/usr/bin/makepkg', '--cleanbuild', '--nodeps', '--nosign', '--noconfirm', '--config',
                  str(Path(contract['invocation']['source']) / contract['makepkg_config']['path'])]
        need(argv == wanted and command.get('cwd') == str(slot) and command['expected'] == 0
             and b'Starting check()' in raw
             and [int(n) for n in re.findall(rb'(?m)^Ran ([0-9]+) tests? in [^\r\n]+\r?$', raw)] == [8]
             and len(re.findall(rb'(?m)^OK\r?$', raw)) == 1 and not re.search(rb'(?:skipped|SKIP|FAILED|ERROR)',raw), 'actual8 original checks without skip/fallback')
        info_index, info_command = selected('srcinfo-'+label)
        info_raw=view.read(prefix+info_command['log'])
        need(info_index<index and info_command['cwd']==str(slot) and info_command['expected']==0
             and info_command['argv']==['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(slot),'/usr/bin/makepkg','--printsrcinfo','--config',str(Path(contract['invocation']['source'])/contract['makepkg_config']['path'])]
             and pin(info_raw)=={key:recipe['source_files']['.SRCINFO'][key] for key in ('bytes','sha256')}
             and build.get('srcinfo')==pin(info_raw),'actual derived metadata equals frozen original .SRCINFO')
        decode_index, decode = selected('archive-' + label)
        need(decode['argv'] == ['/usr/bin/zstd', '-dc', str(fixed/'build-inputs'/label/recipe['archive'])]
             and decode['expected'] == 0 and decode_index > indexes[-1], 'raw actual archive decoder command required')
        raw_tar = view.read(prefix + decode['log']); need(len(raw_tar) <= 2*1024**2, 'bounded actual decoded package DATA')
        payload = {}; metadata = {}; seen = set(); directories = set()
        ancestors = {str(parent) for leaf in expected for parent in Path(leaf).parents if str(parent) != '.'}
        with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:') as archive_data:
            for member in archive_data:
                name = member.name
                need(name not in seen and member.uid == member.gid == 0 and not member.pax_headers, 'unique root-owned archive members'); seen.add(name)
                if member.isdir():
                    need(member.mode == 0o755 and name.rstrip('/') in ancestors, 'finite root-owned package directory')
                    directories.add(name.rstrip('/')); continue
                need(member.isfile() and member.size <= 1024**2, 'ordinary bounded package member')
                body = archive_data.extractfile(member).read(); need(len(body) == member.size, 'complete actual archive member')
                if name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
                    need(member.mode == 0o644, 'ordinary makepkg metadata mode'); metadata[name] = body
                else:
                    need(name in expected and member.mode == expected[name]['mode'] and pin(body) == {key: expected[name][key] for key in ('bytes', 'sha256')}, 'exact source-bound payload bytes/mode')
                    payload[name] = dict(mode=member.mode, **pin(body))
        need(set(payload) == set(expected) and directories == ancestors and set(metadata) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'complete 14-file archive namespace required')
        info = measurement_metadata(metadata['.PKGINFO']); provenance = measurement_metadata(metadata['.BUILDINFO'])
        need(info.get('pkgname') == ['cachy-asahi-measurement-tools'] and info.get('pkgbase') == ['cachy-asahi-measurement-tools'] and info.get('pkgver') == ['0.1.0-1'] and info.get('arch') == ['any']
             and info.get('license') == ['MIT'] and info.get('depend') == ['python>=3.12']
             and info.get('checkdepend') == ['bubblewrap'], 'exact package identity and runtime dependency metadata')
        need(provenance.get('format') == ['2'] and provenance.get('pkgname') == ['cachy-asahi-measurement-tools']
             and provenance.get('pkgbase') == ['cachy-asahi-measurement-tools'] and provenance.get('pkgver') == ['0.1.0-1'] and provenance.get('pkgarch') == ['any']
             and provenance.get('pkgbuild_sha256sum') == [recipe['source_files']['PKGBUILD']['sha256']]
             and sorted(provenance.get('installed', [])) == contract['buildinfo_installed'] and len(provenance.get('installed', [])) == 349
             and 'check' in provenance.get('buildenv', []) and '!check' not in provenance.get('buildenv', []), 'full349 build provenance and checks required')
        actual = dict(archive=archives[label], pkginfo=pin(metadata['.PKGINFO']), buildinfo=pin(metadata['.BUILDINFO']), mtree=pin(metadata['.MTREE']), payload=payload)
        need(comparison.get('builds', {}).get(label) == actual, 'comparison must join every raw actual archive member')
        decoded[label] = (payload, metadata)
    need(indexes == sorted(set(indexes)) and identities[0] != identities[1] and decoded['a'] == decoded['b']
         and archives['a'] == archives['b'] == comparison.get('archive'), 'two distinct ordered builds with exact archive/metadata/payload equality')
    need(comparison.get('pkginfo_text') == decoded['a'][1]['.PKGINFO'].decode() and comparison.get('buildinfo_text') == decoded['a'][1]['.BUILDINFO'].decode()
         and base64.b64decode(comparison.get('mtree_base64', ''), validate=True) == decoded['a'][1]['.MTREE'], 'complete raw provenance DATA must match')
    return indexes, archives


def measurement_restoration(report):
    restore = report.get('restore'); keys = {'alpm_db', 'alarm_home', 'root_home', 'global_trust', 'global_config', 'package_cache'}
    need(type(restore) is dict and set(restore) == keys, 'complete DB/home/trust/config/cache restoration scope required')
    for scope in keys:
        row = restore[scope]
        need(type(row) is dict and set(row) == {'before', 'after', 'unchanged'} and row['unchanged'] is True
             and type(row['before']) is dict and row['before'] == row['after'] and type(row['before'].get('files')) is int
             and row['before']['files'] >= 0 and type(row['before'].get('bytes')) is int and row['before']['bytes'] >= 0
             and re.fullmatch('[0-9a-f]{64}', row['before'].get('sha256') or ''), 'exact full protected snapshot must restore: ' + scope)
    need(report.get('payload_absent') is True and report.get('private_roots_absent') is True and report.get('exports_preserved') is True
         and type(report.get('exports_before')) is dict and report['exports_before'] == report.get('exports_after')
         and report['exports_before'].get('files', 0) > 0, 'all owned payload/private roots absent and operator outputs preserved')



def retained_measurement_alpm(view, files, guest, map_sha256):
    contract=measurement_contract();prefix='journey/measurement-tools-alpm-v1/'
    report=guest.get('measurement_alpm');recipe=contract['recipe'];fixed=T.PREFIX
    need(type(report) is dict and report.get('schema_version')==1 and report.get('operation')==OPERATION
         and report.get('status')==PASS and report.get('source_map_sha256')==map_sha256
         and report.get('version')==T.VERSION and report.get('contract')==pin(read(Path(__file__).with_name('measurement-contract-v1.json')))
         and view.load(prefix+'result.json')==report and report.get('stages')==list(T.STAGES)
         and report.get('first_failure') is None and report.get('namespace_support')=='PASS_ORIGINAL_NATIVE_CHECKS_ONLY',
         'complete same-source native8 check and lifecycle result')
    commands=report.get('commands');selected=measurement_commands(view,files,prefix,commands)
    build_indexes,archives=measurement_build_pair(view,prefix,report,contract,selected,map_sha256)
    paths={label:str(fixed/'build-inputs'/label/recipe['archive']) for label in ('a','b')}
    base=read(Path(__file__).with_name('expected349.lock'));indexes={}
    inventory=report.get('inventory');need(type(inventory) is dict and set(inventory)=={'baseline','installed','repeat','removed','reinstalled','final'},'all six real ALPM inventory states')
    for key in ('baseline','installed','repeat','removed','reinstalled','final'):
        version=T.VERSION if key in ('installed','repeat','reinstalled') else None
        expected=T.inventory_expected(base,version);index,command=selected(key+'-inventory');indexes[key]=index
        need(command['argv']==['/usr/bin/pacman','-Q'] and command['expected']==0
             and b''.join(sorted(view.read(prefix+command['log']).splitlines(keepends=True)))==expected
             and inventory[key]==dict(**pin(expected),count=350 if version else 349,version=version),
             'actual exact inventory349/350 lifecycle')
    need(guest.get('packages')==pin(base),'guest exact349 original base')
    _,command=selected('required-signature-config');config=view.read(prefix+command['log'])
    config_path=command['argv'][1] if len(command['argv'])==2 else ''
    trust=Path(config_path).with_name('trust');work=trust.parent
    need(command['argv']==['/usr/bin/cat',config_path] and work.parent==Path('/tmp')
         and work.name.startswith('measurement-tools-test-') and Path(config_path).name=='pacman.conf'
         and config==('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n').encode()
         and report.get('signature_config')==pin(config) and report.get('signature_policy')==dict(SigLevel='Required',LocalFileSigLevel='Required'),
         'actual scoped TEST Required signature configuration')
    signatures=report.get('signatures');need(type(signatures) is dict and set(signatures)=={'a','b'},'both archive signatures')
    fingerprint=report.get('fingerprint');verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve','--no-auto-key-import','--auto-key-locate','clear','--disable-dirmngr','--no-autostart']
    verifies=[]
    for label in ('a','b'):
        row=signatures[label];strict_test_signature(row.get('status'),fingerprint)
        need(row.get('signer')==fingerprint,'one explicit TEST primary signer')
        signature=base64.b64decode(row['signature']['base64'],validate=True)
        need(0<len(signature)<=65536 and pin(signature)=={key:row['signature'][key] for key in ('bytes','sha256')},'bounded original signature DATA')
        index,command=selected('verify-'+label);verifies.append(index)
        need(command['argv']==verifier+['--status-fd=1','--verify',paths[label]+'.sig',paths[label]] and command['expected']==0
             and view.read(prefix+command['log']).decode()==row['status'],'raw original private TEST verification')
        sign_index,sign=selected('sign-'+label)
        need(max(build_indexes)<sign_index<index and sign['expected']==0 and sign['argv']==['/usr/bin/gpg','--batch','--no-options','--homedir',str(work/'signing'),'--no-auto-key-retrieve','--pinentry-mode','loopback','--passphrase','','--local-user',fingerprint,'--output',paths[label]+'.sig','--detach-sign',paths[label]],
             'signing precedes verification')
    need(max(build_indexes)<min(verifies) and verifies==sorted(set(verifies)),'builds precede ordered signature verification')
    public=report.get('public_key');need(type(public) is dict and public.get('text','').startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----')
         and 'PRIVATE KEY' not in public['text'] and pin(public['text'].encode())=={key:public[key] for key in ('bytes','sha256')},'public TEST certificate only')
    _,command=selected('export-only-test-public');need(view.read(prefix+command['log'])==public['text'].encode() and command['argv'][-3:]==['--armor','--export',fingerprint],'public certificate exact export')
    for step in ('test-primary-fingerprint','trust-key-membership'):
        _,command=selected(step);need([line.split(':')[9] for line in view.read(prefix+command['log']).decode().splitlines() if line.startswith('fpr:')]==[fingerprint],'TEST homes hold sole primary key')
    for step,marker in (('untrusted-signature-control',b'NO_PUBKEY'),('tampered-signature-control',b'BADSIG')):
        _,command=selected(step);raw=view.read(prefix+command['log'])
        need(command['expected']=='nonzero' and '--verify' in command['argv'] and (marker in raw or step=='tampered-signature-control' and b'ERRSIG' in raw),'unknown and tampered GPG refusal')
    need(report.get('alpm_refusals')=={'unknown-key':True,'unsigned':True,'tampered':True},'all three real Required ALPM refusals')
    transaction_indexes={}
    for step,tail in (('install',['-U',paths['a']]),('repeat',['-U',paths['a']]),('remove',['-R',T.NAME]),('reinstall',['-U',paths['b']]),('remove-final',['-R',T.NAME]),('alpm-unknown-key',['-U',paths['a']]),('alpm-unsigned',['-U',str(work/recipe['archive'])]),('alpm-tampered',['-U',str(work/'tampered.pkg.tar.zst')])):
        index,command=selected(step);transaction_indexes[step]=index
        need(command['argv']==['/usr/bin/pacman','--config',config_path,'--noconfirm','--noscriptlet',*tail]
             and command['expected']==('nonzero' if step.startswith('alpm-') else 0),'finite real ALPM transaction under Required policy')
    chain=[indexes['baseline'],*build_indexes,*verifies,transaction_indexes['alpm-unsigned'],transaction_indexes['alpm-tampered'],transaction_indexes['install'],indexes['installed'],transaction_indexes['repeat'],indexes['repeat'],transaction_indexes['remove'],indexes['removed'],transaction_indexes['reinstall'],indexes['reinstalled'],transaction_indexes['remove-final'],indexes['final']]
    need(chain==sorted(set(chain)) and transaction_indexes['alpm-unknown-key']<min(verifies),'actual ordered build/sign/refusal/install/repeat/remove/reinstall/removal')
    need(set(report.get('payloads',{}))=={'installed','repeat','reinstalled'},'each installed state payload receipt')
    for label in ('installed','repeat','reinstalled'):
        expected=dict(version=T.VERSION,count=14,verified=True,stale_absent=True,files={name:{key:item[key] for key in ('bytes','sha256','mode')} for name,item in recipe['payload_files'].items()})
        need(report['payloads'][label]==expected,'each installed state exact14-file payload')
        upper=transaction_indexes[{'installed':'repeat','repeat':'remove','reinstalled':'remove-final'}[label]]
        owners=[]
        for index,command in enumerate(commands):
            if command['step']!=label+'-owner-'+T.NAME:continue
            need(command['argv'][:4]==['/usr/bin/pacman','--config',config_path,'-Qoq'] and len(command['argv'])==5
                 and view.read(prefix+command['log']).strip()==T.NAME.encode() and indexes[label]<index<upper, 'raw real ALPM payload ownership')
            owners.append(command['argv'][-1].lstrip('/'))
        need(sorted(owners)==sorted(recipe['payload_files']),'all14 ownership joins per install state')
        file_index,command=selected(label+'-owned-files-'+T.NAME);names=view.read(prefix+command['log']).decode().splitlines()
        need(indexes[label]<file_index<upper and command['argv']==['/usr/bin/pacman','--config',config_path,'-Qlq',T.NAME] and len(names)==len(set(names))
             and all(name.startswith('/') and '..' not in Path(name).parts and Path(name.rstrip('/')).as_posix()==name.rstrip('/') for name in names)
             and {name.lstrip('/') for name in names if not name.endswith('/')}==set(recipe['payload_files'])
             and {name.strip('/') for name in names if name.endswith('/')}=={str(p) for name in recipe['payload_files'] for p in Path(name).parents if str(p)!='.'},'exact owned payload+directory inventory')
    for key,flag in (('explicit','-Qqe'),('dependencies','-Qqd')):
        pins=[]
        for phase,target in (('baseline-reasons','install_reasons_before'),('restored-reasons','install_reasons_after')):
            _,command=selected(phase+'-'+key);need(command['argv']==['/usr/bin/pacman',flag],'actual install-reason query')
            value=pin(b''.join(sorted(view.read(prefix+command['log']).splitlines(keepends=True))));need(report[target][key]==value,'install-reason raw log pin');pins.append(value)
        need(pins[0]==pins[1],'original package reasons restored')
    measurement_business(view,prefix,report,selected,fixed,indexes['repeat'],transaction_indexes['remove'])
    measurement_restoration(report)
    need(report.get('cleanup')==dict(homes_retired=True,no_sockets=True,private_directory_absent=True,failures=[]),'all owned TEST resources retired')
    for home in ('signing','trust'):
        index,command=selected('retire-'+home);need(index>indexes['final'] and command['expected']==0
             and command['argv']==['/usr/bin/gpgconf','--homedir',str(work/home),'--kill','all'],'scoped TEST retirement after final remove')
        after,command=selected('no-autostart-'+home)
        need(after>index and type(command['expected']) is int and command['expected']==0 and command.get('channels')=='stdout+stderr combined in pipe order' and view.read(prefix+command['log'])==ABSENCE_OUTPUT
             and command['argv']==['/usr/bin/gpg-connect-agent','--homedir',str(work/home),'--no-autostart','/bye'],'original exact zero-exit56B combined-pipe absence observation')
    native=report.get('native');need(type(native) is dict and native.get('architecture')=='aarch64'
         and type(native.get('page_bytes')) is int and native['page_bytes']==guest.get('page_size')>0
         and native.get('execution')=='OWNED_IMAGE_BUILD_STAGE' and native.get('physical_M2')=='NOT_RUN'
         and native.get('release')=='NOT_ADMITTED','native identity; no hardware or release inference')
    return dict(status='MATCHED_MEASUREMENT_TOOLS_ALPM_COMPONENT_DATA_ONLY',version=T.VERSION,
                native='NOT_ADMITTED',native_16K='NOT_QUALIFIED',physical_M2='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')


def measurement_probe_v2(raw,cli,root,contract):
    """Independent finite replay of retained probe DATA; no artifact code imports."""
    def reject_pairs(rows):
        out={}
        for key,value in rows:need(key not in out,'duplicate probe JSON key');out[key]=value
        return out
    def decode(body):
        return json.loads(body,object_pairs_hook=reject_pairs,parse_constant=lambda _:need(False,'nonfinite probe JSON'))
    def natural(state,cap=20):
        need(type(state)is dict and {'exit','reaped','ownership','group_census','output_complete','timeout','signals','error','passed','seconds'}<=set(state)
             and type(state['exit'])is int and state['exit']==0 and state['reaped']is True and state['ownership']=='REAPED'
             and state['group_census']=='EMPTY_TWICE' and state['output_complete']is True
             and state['passed']is True and type(state['seconds'])in(int,float)and 0<=state['seconds']<cap
             and state['timeout']is False and state['signals']==[] and state['error']is None,'probe natural exclusive retirement')
    def canonical(value):return(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    need(type(raw)is bytes and 0<len(raw)<=1024**2,'bounded complete installed probe log')
    p=decode(raw);cli,root=Path(cli),Path(root);fixed=Path('/opt/native-measurement-tools-alpm-v1')
    label='system'if cli==Path('/usr/bin/cachy-asahi-measurement-tools')else'moved'
    expected_cli=Path('/usr/bin/cachy-asahi-measurement-tools')if label=='system'else fixed/'user-data/moved-prefix/usr/bin/cachy-asahi-measurement-tools'
    expected_root=fixed/'user-data'/('system'if label=='system'else'relocated')/'probe'
    need(cli==expected_cli and root==expected_root and p.get('schema')==2 and p.get('status')=='PASS_FINITE_PRIVATE_PID_EMPTY_SYSFS_INSTALLED_PROBE'
         and p.get('cli')==str(cli)and p.get('root')==str(root)and p.get('label')==label,'exact finite installed probe identity')
    need(p.get('helper_sha256')==PRODUCERS['native/measurement_installed_probe_v2.py'] and p.get('owner_sha256')=='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f','source-bound probe and installed owner')
    need(not any(k in p for k in('first_failure','failure','error'))and p.get('comparison')==dict(status='INCOMPLETE',scope='NOT_EXECUTED_ONLY_ONE_OF_TWELVE_SLOTS')
         and p.get('optimization_acceptance')=='NOT RUN' and p.get('workload')=='ONE_OWNED_PRIVATE_PID_SLOT_ONLY'
         and p.get('sensors')=='EMPTY_SYSFS_NO_PHYSICAL_SENSOR_OBSERVATION' and p.get('performance')=='NOT_MEASURED'
         and p.get('physical_M2')=='NOT_RUN' and p.get('release')=='NOT_ADMITTED','probe boundaries and absent comparison credit')
    outer=p.get('outer_pid_namespace');ns=p.get('namespace')
    need(type(outer)is str and re.fullmatch(r'pid:\[[1-9][0-9]*\]',outer) and type(ns)is dict and set(ns)=={'pid','proc_self_pid','pid_namespace','sysfs_entries'}
         and type(ns['pid'])is int and ns['pid']>0 and ns['proc_self_pid']==ns['pid'] and type(ns['proc_self_pid'])is int
         and type(ns['pid_namespace'])is str and re.fullmatch(r'pid:\[[1-9][0-9]*\]',ns['pid_namespace'])and ns['pid_namespace']!=outer
         and ns['sysfs_entries']==[],'private PID/proc and empty sysfs observation')
    prefix=cli.parent.parent;docs=prefix/'share/doc/cachy-asahi-measurement-tools';runtime=prefix/'lib/cachy-asahi/measurement-tools-v1/scripts'
    helper=fixed/'source/native/measurement_installed_probe_v2.py'
    vectors=[('namespace',['/usr/bin/python3','-I','-B',str(helper),'--namespace-check']),
      ('state',[str(cli),'state','--execution-context','unknown','--output',str(root/'base.json')]),
      ('prepare-plan',[str(cli),'benchmark','prepare-plan','--config',str(root/'config.json'),'--baseline',str(root/'base.json'),'--candidate-state',str(root/'candidate.json'),'--output',str(root/'plan.json')]),
      ('trial',[str(cli),'benchmark','run','--plan',str(root/'plan.json'),'--slot','0','--state',str(root/'base.json'),'--conditions',str(root/'conditions.json'),'--cwd',str(root),'--output',str(root/'trial'),'--platform-metrics']),
      ('capture',[str(cli),'metrics','capture','--machine-label','finite private empty-sysfs probe','--duration','.2','--interval','.1','--output',str(root/'capture')]),
      ('summarize',[str(cli),'metrics','summarize','--capture',str(root/'capture'),'--output',str(root/'replay.json')])]
    sandbox=['/usr/bin/bwrap','--die-with-parent','--ro-bind','/','/','--bind',str(root),str(root),'--dev','/dev','--tmpfs','/sys','--unshare-net','--unshare-pid','--proc','/proc','--']
    rows=p.get('commands');need(type(rows)is list and len(rows)==len(vectors),'all finite private probe commands')
    outputs={}
    for row,(step,args)in zip(rows,vectors):
        need(type(row)is dict and set(row)=={'step','argv','expected','supervision','output_base64','output_pin'}and row['step']==step and row['argv']==sandbox+args
             and type(row['expected'])is int and row['expected']==0,'source-defined private namespace command vector')
        natural(row['supervision']);need(type(row['output_base64'])is str and len(row['output_base64'])<=96*1024,'bounded raw probe command output')
        body=base64.b64decode(row['output_base64'],validate=True);need(len(body)<=32*1024 and pin(body)==row['output_pin'],'whole raw bounded private probe output pin');outputs[step]=body
    need(decode(outputs['namespace'])==ns,'actual namespace command log join')
    names={'config.json','conditions.json','base.json','candidate.json','plan.json','replay.json',
      'trial/started.json','trial/trial.json','trial/stdout.txt','trial/stderr.txt','trial/telemetry.jsonl'}
    names|={part+'/'+leaf for part in('trial/platform-metrics','capture')for leaf in('started.json','inventory.json','samples.jsonl','capture.json','summary.json')}
    selected=p.get('files');need(type(selected)is dict and set(selected)==names,'complete finite installed probe file closure')
    bodies={};total=0
    for name,row in selected.items():
        need(type(row)is dict and set(row)=={'bytes','sha256','base64'} and type(row['bytes'])is int and 0<=row['bytes']<=128*1024 and type(row['base64'])is str and len(row['base64'])<=180*1024,'bounded ordinary retained probe body')
        body=base64.b64decode(row['base64'],validate=True);total+=len(body)
        need(pin(body)=={k:row[k]for k in('bytes','sha256')}and total<=512*1024,'whole finite retained probe body pin');bodies[name]=body
    docs_json={n:decode(b)for n,b in bodies.items()if n.endswith('.json')}
    def no_credit(value):
        if type(value)is dict:
            for key,item in value.items():
                if key=='optimization_acceptance':need(item=='NOT RUN','retained probe cannot issue optimization credit')
                if key=='physical_M2':need(item=='NOT_RUN','retained probe cannot issue physical hardware credit')
                if key=='release':need(item=='NOT_ADMITTED','retained probe cannot issue release credit')
                no_credit(item)
        elif type(value)is list:
            for item in value:no_credit(item)
    for doc in docs_json.values():no_credit(doc)
    base=docs_json['base.json'];plan=docs_json['plan.json'];trial=docs_json['trial/trial.json'];config=docs_json['config.json']
    need(bodies['base.json']==bodies['candidate.json'] and base.get('record_type')=='measurement-base-state' and base.get('optimization_acceptance')=='NOT RUN'
         and base.get('execution_context')=='unknown' and base.get('architecture')=='aarch64','exact same unknown nonacceptance base state')
    need(config.get('argv')==['/usr/bin/python3',str(docs/'smoke_workload.py')]and config.get('inputs')==config['argv']and config.get('execution_context')=='unknown'
         and config.get('order')==['baseline','candidate','candidate','baseline','candidate','baseline','baseline','candidate','baseline','candidate','candidate','baseline']
         and type(config.get('minimum_trials'))is int and config['minimum_trials']==5 and config.get('timeout_seconds')==2 and config.get('platform_metrics')=={'interval_seconds':0.1},'frozen single-slot source workload/config bounds')
    need(plan.get('record_type')=='frozen-experiment-plan' and plan.get('config')==config and plan.get('optimization_acceptance')=='NOT RUN'
         and plan.get('baseline_binding')==dict(path=str(root/'base.json'),resolved_path=str(root/'base.json'),sha256=pin(bodies['base.json'])['sha256'])
         and plan.get('candidate_binding')==dict(path=str(root/'candidate.json'),resolved_path=str(root/'candidate.json'),sha256=pin(bodies['candidate.json'])['sha256']),'frozen plan and exact retained state bindings')
    need(pin(bodies['conditions.json'])=={k:contract['recipe']['source_files']['conditions.example.json'][k]for k in('bytes','sha256')},'exact original declared synthetic conditions')
    state={k:base.get(k)for k in('architecture','machine_model','device_tree_compatible','page_size_bytes','kernel','os_release','execution_context','m2_air_size')}
    state.update(packages=base.get('packages',{}).get('stdout')if base.get('packages',{}).get('returncode')==0 else None,repositories=[{'name':r['name'],'sha256':r.get('sha256')}for r in base.get('repositories',{}).get('sync_databases',[])])
    need(plan.get('states')==dict(baseline=state,candidate=state),'frozen state identity equality')
    source_paths={'benchmark.py':runtime/'benchmarks/benchmark.py','benchmark_platform_metrics.py':runtime/'benchmarks/benchmark_platform_metrics.py','platform_metrics.py':runtime/'benchmarks/platform_metrics.py','process_group_memory.py':runtime/'benchmarks/process_group_memory.py','owned_process.py':runtime/'virtual/owned_process.py','smoke_workload.py':docs/'smoke_workload.py'}
    inputs=plan.get('inputs');need(type(inputs)is list and len(inputs)==7 and len({r['path']for r in inputs})==7,'complete seven source/executable plan pins')
    by_path={r['path']:r for r in inputs};need(set(by_path)=={str(v)for v in source_paths.values()}|{'/usr/bin/python3'},'exact installed source/executable input namespace')
    for name,path in source_paths.items():
        row=by_path[str(path)];need(row==dict(path=str(path),resolved_path=str(path),sha256=contract['recipe']['source_files'][name]['sha256']),'exact unchanged installed source plan pin')
    python=by_path['/usr/bin/python3'];need(type(python.get('resolved_path'))is str and python['resolved_path'].startswith('/usr/bin/python3.')and type(python.get('sha256'))is str and re.fullmatch('[0-9a-f]{64}',python['sha256']),'retained interpreter whole input pin')
    need(trial.get('record_type')=='benchmark-trial' and trial.get('valid')is True and type(trial.get('slot'))is int and trial['slot']==0 and trial.get('variant')=='baseline'
         and trial.get('returncode')==0 and type(trial['returncode'])is int and 'error'in trial and trial['error']is None and trial.get('plan_sha256')==pin(bodies['plan.json'])['sha256']
         and trial.get('argv')==config['argv']and trial.get('cwd')==str(root)and trial.get('state')==trial.get('state_after')==state and trial.get('conditions')==docs_json['conditions.json']
         and trial.get('optimization_acceptance')=='NOT RUN' and type(trial.get('metrics'))is dict and 'root_rss_kib'in trial['metrics'] and trial['metrics']['root_rss_kib']is None,'valid real owned private slot without optimization credit')
    need(trial.get('raw_sha256')=={n[len('trial/'):]:pin(b)['sha256']for n,b in bodies.items()if n.startswith('trial/')and n not in('trial/started.json','trial/trial.json')},'all trial raw artifact hashes')
    started=docs_json['trial/started.json'];prelaunch={'schema_version','record_type','plan_sha256','slot','variant','started_at','hostname','machine_id','base_id','workload_id','state','conditions','argv','cwd','environment_sha256','comparable_environment_sha256','declared_environment','execution_label','optimization_acceptance'}
    need(type(started)is dict and set(started)==prelaunch and started['schema_version']==1 and type(started['schema_version'])is int and all(trial.get(k)==v for k,v in started.items()),'actual complete prelaunch trial record join')
    source_pins={k:contract['recipe']['source_files'][n]['sha256']for k,n in(('collector_sha256','platform_metrics.py'),('owner_sha256','owned_process.py'),('adapter_sha256','benchmark_platform_metrics.py'))}
    need(trial.get('platform_metrics',{}).get('schema')=='benchmark-platform-metrics-v1' and trial['platform_metrics'].get('source_pins')==source_pins and trial['platform_metrics'].get('optimization_acceptance')=='NOT RUN','unchanged platform collector/owner/adapter source pins')
    sampling=trial.get('sampling_status');need(type(sampling)is dict and set(sampling)=={'worker_stopped','workload_reaped','error','dropped_samples'}and sampling['worker_stopped']is True and sampling['workload_reaped']is True and sampling['error']is None and type(sampling['dropped_samples'])is int and sampling['dropped_samples']==0,'actual stopped collector and reaped workload')
    for part in('trial/platform-metrics','capture'):
        inventory=docs_json[part+'/inventory.json'];capture=docs_json[part+'/capture.json'];summary=docs_json[part+'/summary.json']
        need(inventory.get('schema')=='cachy-asahi-platform-metrics-v1' and inventory.get('sysfs_root')=='/sys'and inventory.get('sensors')==[]and inventory.get('devices')==[]
             and set(inventory.get('classes',{}))=={'power_supply','thermal','hwmon'}and all(v.get('status')=='absent' and v.get('devices')==[]for v in inventory['classes'].values()),'actual empty-sysfs absent-class sensor inventory')
        need(capture.get('schema')==('benchmark-platform-metrics-v1'if part=='trial/platform-metrics'else'cachy-asahi-platform-metrics-v1') and capture.get('completed')is True and 'failure'not in capture
             and capture.get('files')=={n:pin(bodies[part+'/'+n])for n in('inventory.json','samples.jsonl')},'whole completed platform capture inputs')
        lines=bodies[part+'/samples.jsonl'].splitlines();need(2<=len(lines)<=64,'finite real platform sample sequence')
        previous=None;samples=[]
        for index,line in enumerate(lines):
            sample=decode(line);start=sample.get('start',{}).get('monotonic_ns');end=sample.get('end',{}).get('monotonic_ns')
            need(type(sample.get('sequence'))is int and sample['sequence']==index and sample.get('readings')==[]and type(start)is int and type(end)is int and 0<start<=end and(previous is None or previous<=start),'ordered empty-sensor raw samples');previous=end;samples.append(sample)
            need(set(sample['start'])==set(sample['end'])=={'monotonic_ns','boottime_ns','realtime_ns'}and all(type(point[k])is int and point[k]>0 for point in(sample['start'],sample['end'])for k in point)and all(sample['end'][k]>=sample['start'][k]for k in sample['start'])and(index==0 or all(sample['start'][k]>samples[index-1]['end'][k]for k in sample['start'])),'complete ordered observed platform clocks')
        need(summary.get('schema')=='cachy-asahi-platform-metrics-v1'and type(summary.get('sensor_count'))is int and summary['sensor_count']==0 and summary.get('sensors')==[],'empty-sensor summary no physical observation')
        began=docs_json[part+'/started.json'];need(type(began)is dict and began.get('completed')is False and began.get('schema')==capture['schema'],'actual incomplete prelaunch capture')
        need(set(began)==({'schema','completed','machine_before','collector_sha256','owner_sha256','adapter_sha256','max_gap_seconds','interval_seconds_requested'}if part=='trial/platform-metrics'else{'schema','completed','machine_label','machine_label_source','notes','references','machine','collector','duration_seconds_requested','interval_seconds_requested','max_gap_seconds','start','limits'})and all(capture.get(k)==v for k,v in began.items()if k!='completed'),'whole capture prelaunch record join')
        if part=='trial/platform-metrics':
            natural(capture.get('supervision'),2.5);accounting=capture.get('sampling');need(type(accounting)is dict and set(accounting)=={'bytes','error','snapshot_seconds'}and type(accounting['bytes'])is int and accounting['bytes']==len(bodies[part+'/samples.jsonl']) and accounting['error']is None and type(accounting['snapshot_seconds'])is list and len(accounting['snapshot_seconds'])==len(lines)and all(type(n)in(int,float)and 0<=n<2.5 for n in accounting['snapshot_seconds']),'actual finite platform sample accounting')
            binding=trial['platform_metrics'].get('binding');need(type(binding)is dict and set(binding)=={'machine_before','machine_after','start','end','argv_sha256','cwd'}and binding==capture.get('workload') and binding['machine_before']==binding['machine_after']==capture.get('machine_before')==capture.get('machine_after') and binding['argv_sha256']==hashlib.sha256(canonical(config['argv'])).hexdigest()and binding['cwd']==str(root),'actual workload/capture machine argv directory binding')
            start,end=binding['start'],binding['end'];need(type(start)is dict and type(end)is dict and set(start)==set(end)=={'monotonic_ns','boottime_ns','realtime_ns'}and all(type(point[k])is int and point[k]>0 for point in(start,end)for k in point)and all(end[k]>start[k]for k in start),'complete natural workload clock boundaries')
            elapsed=end['monotonic_ns']-start['monotonic_ns'];need(all(abs((end[k]-start[k])-elapsed)<=50000000 for k in('boottime_ns','realtime_ns'))and samples[0]['end']['monotonic_ns']<=start['monotonic_ns']<end['monotonic_ns']<=samples[-1]['start']['monotonic_ns']and trial.get('monotonic_start_ns')==start['monotonic_ns']and trial.get('monotonic_end_ns')==end['monotonic_ns']and trial.get('elapsed_ns')==elapsed and summary.get('window_monotonic_start_ns')==start['monotonic_ns']and summary.get('window_monotonic_end_ns')==end['monotonic_ns'],'actual raw samples bracket the joined owned workload')
            for point,observed in((start,samples[0]['end']),(end,samples[-1]['start'])):need(all(abs((point[k]-point['monotonic_ns'])-(observed[k]-observed['monotonic_ns']))<=50000000 for k in('boottime_ns','realtime_ns')),'workload/capture clock origins agree')
            need(capture.get('unresolved_wait_pid')is None and 'unresolved_wait_pid'in capture and capture.get('worker_stopped')is True
                 and capture.get('collector_sha256')==source_pins['collector_sha256']and capture.get('owner_sha256')==source_pins['owner_sha256']and capture.get('adapter_sha256')==source_pins['adapter_sha256'],'native owned workload capture and source join')
        else:need(type(capture.get('sample_count'))is int and capture['sample_count']==len(lines) and capture.get('collector')=={k:contract['recipe']['source_files']['platform_metrics.py'][k]for k in('bytes','sha256')}
                  and capture.get('duration_seconds_requested')==0.2 and capture.get('interval_seconds_requested')==0.1,'fixed standalone collector and duration')
    telemetry=decode(bodies['trial/telemetry.jsonl']);need(telemetry.get('monotonic_ns')==trial['monotonic_start_ns']and telemetry.get('memory')==dict(root_rss_kib=None,lifecycle='unknown')and telemetry.get('thermal')==telemetry.get('power')==telemetry.get('battery')==[]and telemetry.get('missing')==['memory','thermal','power','battery'],'missing guardrail telemetry stays unknown')
    replay=docs_json['replay.json'];need(replay==dict(docs_json['capture/summary.json'],inputs=docs_json['capture/capture.json']['files']),'standalone raw capture exact replay summary')
    return dict(status='MATCHED_FINITE_PRIVATE_PID_EMPTY_SYSFS_INSTALLED_PROBE_DATA_ONLY',files=len(bodies),commands=len(rows),trial_slot=0,comparison='INCOMPLETE_NOT_EXECUTED',optimization_acceptance='NOT RUN')


def measurement_business(view,prefix,report,selected,fixed,after,before):
    need(set(report.get('business',{}))=={'system','moved'},'both installed and relocated CLI checks')
    for label in ('system','moved'):
        result=report['business'][label]
        cli=Path('/usr/bin')/T.NAME if label=='system' else fixed/'user-data/moved-prefix/usr/bin'/T.NAME
        root=fixed/'user-data'/('system' if label=='system' else 'relocated')
        need(result.get('status')=='PASS_FINITE_INSTALLED_CLI' and result.get('cli')==str(cli)
             and result.get('workload')=='ONE_OWNED_PRIVATE_PID_SLOT_ONLY' and result.get('sensors')=='EMPTY_SYSFS_NO_PHYSICAL_SENSOR_OBSERVATION' and result.get('performance')=='NOT_MEASURED'
             and result.get('physical_M2')=='NOT_RUN' and result.get('release')=='NOT_ADMITTED'
             and result.get('refusals')=={'existing-state':True,'legacy-run':True},'finite CLI component boundaries')
        operations={'version':(['--version'],0),'help':(['--help'],0),'run-help':(['benchmark','run','--help'],0),
                    'metrics-help':(['metrics','capture','--help'],0),'state':(['state','--execution-context','unknown','--output',str(root/'state.json')],0),
                    'existing-state':(['state','--execution-context','unknown','--output',str(root/'state.json')],2),'legacy-run':(['benchmark','run'],2)}
        need(set(result.get('steps',{}))==set(result.get('reports',{}))==set(operations)|{'state-document','private-probe'},'complete finite CLI command set')
        for key,(args,code) in operations.items():
            need(result['steps'][key]==label+'-'+key,'source-defined CLI step')
            index,command=selected(label+'-'+key)
            need(after<index<before and command['expected']==code and command['cwd']==str(root)
                 and command['argv']==['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(root),'PATH=/usr/bin:/bin',str(cli),*args]
                 and pin(view.read(prefix+command['log']))==result['reports'][key],'actual ordinary-user CLI output and context')
            raw=view.read(prefix+command['log'])
            if key=='version':need(raw.strip()==(T.NAME+' 0.1.0').encode(),'version output')
            if key=='legacy-run':need(b'requires --platform-metrics' in raw,'legacy workload refusal')
            if key=='existing-state':need(b'refused' in raw,'freshness refusal')
        index,command=selected(label+'-state-document');raw=view.read(prefix+command['log'])
        need(after<index<before and command['expected']==0 and command['argv']==['/usr/bin/cat',str(root/'state.json')]
             and result['steps']['state-document']==label+'-state-document' and result['reports']['state-document']==pin(raw)
             and result['state_pin']==pin(raw) and json.loads(raw)==result['state'],'raw retained state DATA join')
        need(result.get('state',{}).get('record_type')=='measurement-base-state' and result['state'].get('optimization_acceptance')=='NOT RUN','identity DATA no optimization inference')
        index,command=selected(label+'-private-probe');raw=view.read(prefix+command['log']);helper=fixed/'source/native/measurement_installed_probe_v2.py'
        need(after<index<before and command['expected']==0 and command['cwd']==str(root)
             and command['argv']==['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(root),'PATH=/usr/bin:/bin','/usr/bin/python3','-I','-B',str(helper),'--cli',str(cli),'--root',str(root/'probe'),'--label',label]
             and result['steps']['private-probe']==label+'-private-probe' and result['reports']['private-probe']==pin(raw)
             and json.loads(raw)==result.get('private_probe'),'raw retained installed probe command and artifact report join')
        measurement_probe_v2(raw,cli,root/'probe',measurement_contract())

def validate(capsule_path, expected):
    """External digest plus actual source/ref/run/map required before capsule I/O."""
    global PRODUCERS
    need(type(expected) is dict and set(expected)=={'source','ref','run','map_sha256','capsule_sha256'}
         and re.fullmatch('[0-9a-f]{40}',expected.get('source') or '')
         and type(expected.get('ref')) is str and expected['ref'].startswith('refs/heads/codex/')
         and re.fullmatch('[1-9][0-9]*',expected.get('run') or '')
         and all(type(expected.get(key)) is str and re.fullmatch('[0-9a-f]{64}',expected[key])
                 for key in ('map_sha256','capsule_sha256')),'NULL/unbound actual selectors or external capsule digest refused before reading')
    root=Path(__file__).resolve().parents[1];source=verify_source(root,expected['map_sha256'])
    PRODUCERS={name:row['sha256'] for name,row in source['files'].items()}
    need(T.data_pin(T.ordinary(capsule_path,32*1024**2))['sha256']==expected['capsule_sha256'],
         'external exact capsule digest differs')
    view=open_capsule(capsule_path);binding={key:expected[key] for key in ('source','ref','run')}
    binding.update(attempt=1,token=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24])
    manifest=view.load('artifacts.json')
    need(manifest.get('schema')==1 and manifest.get('binding')==binding and manifest.get('source_map_sha256')==expected['map_sha256'],'capsule source/ref/run/map binding')
    files=manifest.get('files');need(type(files) is dict and 0<len(files)<=3000
         and all(type(row) is dict and type(row.get('bytes')) is int and 0<=row['bytes']<=16*1024**2
                 and re.fullmatch('[0-9a-f]{64}',row.get('sha256') or '') for row in files.values())
         and sum(row['bytes'] for row in files.values())<=32*1024**2,'bounded DATA manifest')
    view.verify_manifest(manifest)
    if 'safe-diagnostic.json' in files:
        return retained_safe_diagnostic(view,files,binding,expected['map_sha256'])
    if 'provision-diagnostic.json' in files:
        from reader import retained_public_projection as inherited_projection
        need(all(name in {'provision-diagnostic.json','public-projection.json','transport-diagnostic.json','transport-proof.json'}
                 or re.fullmatch(r'provision-logs/(?:proof\.json|input-transport-owner\.json|input-cache-owner\.json)-[0-9]{3}\.log',name)
                 or re.fullmatch(r'transport-proof/(?:receipt\.json|[0-9]{4}\.(stdout|stderr))',name) for name in files),
             'closed original191 provisioning diagnostic namespace')
        inherited_projection(view,files,binding,expected['map_sha256'])
        value=view.load('provision-diagnostic.json');phase=value.get('phases',{}).get('input-transport-owner.json')
        if phase is not None:retained_transport_diagnostic(view,files,phase,binding,expected['map_sha256'])
        need(value.get('binding')==binding and value.get('source_map_sha256')==expected['map_sha256']
             and value.get('status')=='DIAGNOSTIC_HOSTED_INPUT_PROVISIONING_ONLY'
             and value.get('native')==value.get('GPG')==value.get('ALPM')=='NOT_RUN','original provisioning DATA only')
        return dict(status='VALIDATED_INPUT_PROVISIONING_DIAGNOSTIC_NOT_NATIVE',binding=binding,native='NOT_RUN',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    retained_public_projection(view,files,binding,expected['map_sha256'])
    receipt=view.load('receipt.json');cleanup=view.load('cleanup.json')
    need(receipt.get('binding')==cleanup.get('binding')==binding
         and receipt.get('source_map_sha256')==cleanup.get('source_map_sha256')==expected['map_sha256'],
         'actual same-source owner and cleanup outcomes')
    diagnostic=retained_consumer_diagnostic(view,files,receipt,binding,expected['map_sha256'])
    if receipt.get('status')!=PASS or cleanup.get('status')!='PASS_EXACT_OWNED_RESOURCES_RETIRED' or not diagnostic['positive_candidate']:
        return dict(status='VALIDATED_NATIVE_FAILURE_DATA_ONLY',binding=binding,owner_status=receipt.get('status'),
                    cleanup_status=cleanup.get('status'),consumer_diagnostic=diagnostic,native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    retained_consumer_diagnostic(view,files,receipt,binding,expected['map_sha256'],positive=True)
    retained_failure_data(view,files,receipt.get('bootstrap_failure_data'),binding,expected['map_sha256'])
    retained_image_lifecycle(view,files,receipt,cleanup,binding,expected['map_sha256'])
    runner=view.load('bootstrap-proof/bootstrap-runner.json')
    need(runner['kernel']['machine'] in ('aarch64','arm64') and runner['docker_server_arch'] in ('aarch64','arm64')
         and runner['commit']==binding['source'] and runner['run_id']==binding['run']
         and runner['docker_endpoint'] in ('unix:///var/run/docker.sock','unix:///run/docker.sock')
         and type(runner['page_size']) is int and runner['page_size']>0,'actual ARM host and local Docker provenance')
    before=view.load('consumer-inspect.json');after=view.load('consumer-after.json')
    for row in (before,after):
        need(row['Id']==receipt['consumer']['container'],'same exact consumer container')
        consumer_contract(row,binding,receipt['consumer']['image'],receipt['source_root'],receipt['output_root'],runner['uid'],runner['gid'])
    need(after['State']==receipt['consumer']['state'] and after['State']['Running'] is False
         and after['State']['ExitCode']==0 and after['State']['Status']=='exited','completed original consumer daemon state')
    phases=receipt['provisioning'];retained_transport_proof(view,files,phases['transport'],binding,expected['map_sha256'])
    need(phases['proof']['status']=='PASS_EXACT_PUBLISHED_SOURCE_PROOF_ONLY'
         and phases['transport']['status']=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'
         and phases['cache']['status']=='PASS_EIGHT_INPUT_CACHE_DATA_ONLY','complete original provisioning phases')
    for phase in phases.values():need(phase['binding']==binding and phase['source_map_sha256']==expected['map_sha256'],'all phase source bindings')
    for row in phases['proof']['actors']+phases['transport']['actors']+receipt['actors']+cleanup['actors']:
        need(row.get('public_log') in files and files[row['public_log']]['kind']=='file'
             and row.get('status')=='PASS' and type(row.get('exit')) is int and row['exit']==0
             and all(row.get(key) is True for key in ('natural_exit','group_absent','exit_observed_via_waitpid','leader_held_until_group_inspection'))
             and row.get('retirement')=='REAPED' and row.get('ownership_lost') is False and row.get('forced_cleanup') is False
             and pin(view.read(row['public_log']))==row.get('log_pin'),'original raw actor logs and natural owned retirement')
    guest=view.load('journey/result.json')
    need(guest.get('status')==PASS and guest.get('operation')==OPERATION and guest.get('source_map_sha256')==expected['map_sha256']
         and guest.get('architecture')=='aarch64' and guest.get('packages')==receipt['input_inventory']
         and guest.get('system_install')=='IMAGE_STAGE_ALPM_ONLY' and guest.get('native_16K')=='NOT_QUALIFIED'
         and guest.get('physical_M2')=='NOT_RUN' and guest.get('performance')=='NOT_MEASURED' and guest.get('release')=='NOT_ADMITTED',
         'actual finite guest component boundaries')
    component=retained_measurement_alpm(view,files,guest,expected['map_sha256'])
    return dict(status='VALIDATED_NATIVE_MEASUREMENT_TOOLS_ALPM_COMPONENT_EVIDENCE_ONLY',binding=binding,
                measurement_tools=component,native='NOT_ADMITTED',native_16K='NOT_QUALIFIED',physical_M2='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capsule',type=Path,required=True);parser.add_argument('--binding',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(validate(args.capsule,load(args.binding)),sort_keys=True))
