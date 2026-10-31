# SPDX-License-Identifier: MIT
"""Pure accepted Boot79 DATA inspection; never import or execute carrier source."""
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

SOURCE = '2c524830adb007e3b49392ceb54dd4cc5236c77d'
REF = 'codex/boot-report-native-products-v1'
RUN = 39323942218
NAME = 'cachy-asahi-boot-report'
VERSION = '0.1.0-1'
INDEX = dict(bytes=24491, sha256='df27cff377e3c53e209cc07cef55202e859c1002570b9699aaccf39db4d73da3')
ARCHIVE = dict(bytes=13920, sha256='4400e766391b27021c6f40d29c35eb215d9fad12e4555f0d8b6637967baa6472')
PAYLOAD = {'usr/bin/'+NAME: (NAME, 0o755),
           'usr/share/doc/'+NAME+'/README.md': ('README.md', 0o644),
           'usr/share/licenses/'+NAME+'/LICENSE': ('LICENSE', 0o644),
           'usr/share/licenses/'+NAME+'/NOTICE': ('NOTICE', 0o644)}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def relative(name):
    need(type(name) is str and name and not name.startswith('/') and
         Path(name).as_posix() == name and not {'.', '..'} & set(name.split('/')),
         'contained ordinary relative DATA')
    return name

def read(path, maximum=16*1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute ordinary DATA')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            key = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            before = os.fstat(leaf)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                 'bounded single-link ordinary DATA')
            result = bytearray()
            while len(result) <= before.st_size:
                block = os.read(leaf, min(65536, before.st_size-len(result)+1))
                if not block:
                    break
                result.extend(block)
            need(len(result) == before.st_size and key(before) == key(os.fstat(leaf)) ==
                 key(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'DATA identity drift')
            return bytes(result)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)

def inspect(root, checks):
    """checks is the unchanged source-owned package inspector, never carrier code."""
    root = Path(root).absolute()
    raw_index = read(root/'index.json', 1024**2)
    need(pin(raw_index) == INDEX, 'exact Root-published carrier index')
    index = decode(raw_index)
    need(index['schema_version'] == 1 and index['kind'] == 'BOOT_REPORT_ACCEPTED_NATIVE_PAIR_INPUTS_ONLY' and
         index['authority_scope'] == 'UNSIGNED_ACCEPTED_PAIR_NO_CURRENT606_CREDIT' and
         index['native'] == dict(source=SOURCE, ref=REF, run=RUN, source_files=79), 'finite accepted input authority')
    files = index['files']
    entries = list(root.rglob('*'))
    need(len(files) == 122 and all(not p.is_symlink() for p in entries) and
         {p.relative_to(root).as_posix() for p in entries if p.is_file()} == set(files)|{'index.json'},
         'whole123 carrier closure')
    raw = {}
    for name, expected in files.items():
        relative(name)
        need(type(expected) is dict and set(expected) == {'bytes','sha256'}, 'typed DATA pin')
        raw[name] = read(root/name)
        need(pin(raw[name]) == expected, 'whole carrier DATA drift: '+name)
    need(sum(map(len, raw.values())) + len(raw_index) == 10382105, 'complete carrier byte count')
    def referenced(row):
        need(type(row) is dict and set(row) == {'path','bytes','sha256'}, 'closed index reference')
        name = relative(row['path'])
        need(name in raw and pin(raw[name]) == {k:row[k] for k in ('bytes','sha256')}, 'index reference join')
        return raw[name]
    for key in ('decision','source_authorization','git_source_authorization','publication','original_artifact'):
        referenced(index[key])
    for row in index['original_metadata'].values():
        referenced(row)
    auth = decode(referenced(index['source_authorization']))
    git = decode(referenced(index['git_source_authorization']))
    publication = decode(referenced(index['publication']))
    need(len(auth) == 79 and git == dict(files=auth, source=SOURCE, ref=REF,
         status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'), 'whole79 source/Git authorization')
    need(publication == dict(actual='NOT_RUN', files=79, git_joins=79, hardware='NOT_RUN', ref=REF,
         release='NOT_ADMITTED', source=SOURCE, status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'), 'genuine79 publication')
    need({name.removeprefix('source/') for name in raw if name.startswith('source/')} == set(auth), 'whole source role closure')
    for name, expected in auth.items():
        need(pin(raw['source/'+relative(name)]) == expected, 'source authorization bytes')
    run = decode(raw['original/run.json'])
    need((run['id'],run['head_sha'],run['head_branch'],run['run_attempt'],run['status'],run['conclusion']) ==
         (RUN,SOURCE,REF,1,'completed','success'), 'original successful run source/attempt')
    jobs = decode(raw['original/jobs.json'])
    need(jobs['total_count'] == len(jobs['jobs']) == 1, 'sole original native job')
    job = jobs['jobs'][0]
    need((job['run_id'],job['head_sha'],job['head_branch'],job['run_attempt'],job['name'],job['labels'],job['status'],job['conclusion']) ==
         (RUN,SOURCE,REF,1,'native',['ubuntu-24.04-arm'],'completed','success'), 'original native job join')
    steps = {r['number']:r for r in job['steps']}
    for number in (3,8,9,10,11,12,13,14,15):
        need(steps[number]['status'] == 'completed' and steps[number]['conclusion'] == 'success', 'original required source/native/retirement/upload step')
    need(steps[12]['name'] == 'Native Boot fresh build pair and installed synthetic CLI lifecycle' and
         steps[14]['completed_at'] <= steps[15]['completed_at'], 'original product/retention/upload step order')
    artifacts = decode(raw['original/artifacts.json'])
    need(artifacts['total_count'] == len(artifacts['artifacts']) == 1, 'sole original artifact API role')
    artifact = artifacts['artifacts'][0]
    need(artifact['name'] == 'boot-report-native-products-'+str(RUN)+'-1' and artifact['expired'] is False and
         artifact['size_in_bytes'] == len(raw['original/artifact.zip']) and
         artifact['digest'] == 'sha256:'+pin(raw['original/artifact.zip'])['sha256'] and
         artifact['workflow_run']['id'] == RUN and artifact['workflow_run']['head_sha'] == SOURCE and
         artifact['workflow_run']['head_branch'] == REF, 'original ZIP/API digest/source join')
    with zipfile.ZipFile(root/'original/artifact.zip') as archive:
        members = archive.infolist()
        need(len(members) == 35 and len({m.filename for m in members}) == 35 and archive.testzip() is None,
             'whole original ZIP count/uniqueness/CRC')
        need({'retained/'+m.filename for m in members} == {n for n in raw if n.startswith('retained/')}, 'whole35 retained original roles')
        for member in members:
            relative(member.filename)
            mode = member.external_attr >> 16
            need(not member.is_dir() and not member.flag_bits & 1 and not stat.S_ISLNK(mode) and
                 member.file_size <= 16*1024**2 and archive.read(member) == raw['retained/'+member.filename], 'exact ordinary ZIP member bytes')
    retained = decode(raw['retained/retention.json'])
    need(retained['errors'] == [] and retained['status'] == 'PASS_NATIVE_PRODUCT_CANDIDATES_CLI_LIFECYCLE' and
         set(retained['files']) == {n.removeprefix('retained/') for n in raw if n.startswith('retained/')} - {'retention.json'}, 'complete old retention protocol')
    for name, expected in retained['files'].items():
        need(pin(raw['retained/'+name]) == expected, 'old retainer file hash')
    decision = decode(referenced(index['decision']))
    need(decision['status'] == 'ROOT_ACCEPTED_FINITE_NATIVE_BOOT_REPORT_PAIR_AND_SYNTHETIC_INSTALLED_CLI_LIFECYCLE' and
         decision['source'] == SOURCE and decision['run'] == RUN, 'exact accepted native component decision')
    package = index['package']
    need((package['name'],package['version']) == (NAME,VERSION), 'exact selected product')
    reports, paths = [], []
    for side in ('a','b'):
        data = referenced(package['archives'][side])
        need(pin(data) == ARCHIVE, 'exact accepted unsigned pair bytes')
        path = root/package['archives'][side]['path']
        report = checks.package(path)
        need(not report['errors'] and not report['elf'], 'complete original static package inspector')
        meta = report['metadata']['.PKGINFO']
        need(meta['pkgname'] == [NAME] and meta['pkgver'] == [VERSION] and meta['arch'] == ['any'] and
             meta['license'] == ['MIT'] and meta['depend'] == ['python>=3.11','systemd>=251'] and
             not any(meta.get(k) for k in ('conflict','replaces','backup','install')), 'exact finite dependency/metadata contract')
        payload = {n:r for n,r in report['members'].items() if r['type'] != '5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}
        need(set(payload) == set(PAYLOAD), 'complete four installed payload leaves')
        for name, (source, mode) in PAYLOAD.items():
            member = payload[name]
            need(member['type'] == '0' and member['uid'] == member['gid'] == 0 and member['mode'] == mode and
                 dict(bytes=member['size'],sha256=member['sha256']) == pin(raw['source/packages/tools/'+NAME+'/'+source]), 'whole payload/source/license join')
        need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum'] == [auth['packages/tools/'+NAME+'/PKGBUILD']['sha256']], 'actual BUILDINFO recipe hash')
        validation = decode(referenced(package['validation'][side]))
        need(validation['errors'] == [] and validation['package'] == report, 'complete original package validation equality')
        provenance = decode(referenced(package['provenance'][side]))
        need(provenance['mode'] == 'native' and provenance['status'] == 'built-package-static-pass' and
             provenance['recipe_inputs']['PKGBUILD'] == auth['packages/tools/'+NAME+'/PKGBUILD']['sha256'], 'whole native provenance recipe join')
        reports.append(report)
        paths.append(path)
    need(paths[0].read_bytes() == paths[1].read_bytes() and reports[0] == reports[1], 'complete distinct native pair equality')
    comparison = decode(referenced(package['comparison']))
    need(comparison['errors'] == [] and comparison['status'] == 'contents-reproduced' and
         all(comparison['packages'][paths[0].name].values()), 'original pair comparison')
    return dict(archive=paths[0], payload={n:r for n,r in reports[0]['members'].items() if n in PAYLOAD},
                source=SOURCE, run=RUN, index=INDEX, accepted_pair=ARCHIVE,
                authority='ACCEPTED_INPUTS_ONLY_NO_NEW_CURRENT606_OR_NATIVE_ACCEPTANCE')
