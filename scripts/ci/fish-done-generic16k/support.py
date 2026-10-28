# SPDX-License-Identifier: MIT
"""Pinned source-only reuse for the private Fish Done 16 KiB CLI trial."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
MAP_SHA='47e1cd37bb11790dad7758e3c259f45929f53841bb789268b6d4bb75612603d1'
TOOLS=('bash','env','uname','getconf','mount','python3','fish','sleep','sh','timeout','kill','mkdir','rm','ln')
SCOPE='PRIVATE_GENERIC_ARM64_16K_FISH_DONE_NATIVE_C_RECORDER_ADAPTED_PTY_ONLY'
STATUS='PASS_GENERIC_16K_FISH_DONE_NATIVE_C_RECORDER_ADAPTED_PTY_ONLY'
TRANSPORT='PRIVATE_NATIVE_C_NOTIFY_SEND_RECORDER_ONLY'
RECORDER='fixtures/notify-recorder'
ADAPTED='fixtures/done-native.py'
SOURCE='fixtures/notify_recorder.c'
ADAPTER='fixtures/recorder_adapter.py'
COMPILE=['/usr/bin/cc','-std=c11','-D_POSIX_C_SOURCE=200809L','-Wall','-Wextra','-Werror','-O2',
    '-Wl,-z,max-page-size=16384','/source/notify_recorder.c','-o','/out/notify-recorder']


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(data):return hashlib.sha256(data).hexdigest()


def read(path,cap=1024**2):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=cap,'regular bounded input required')
    with path.open('rb') as stream:raw=stream.read(cap+1)
    need(len(raw)<=cap,'input byte bound');return raw


def save(path,value,cap=2*1024**2):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=cap,'receipt byte bound')
    Path(path).write_bytes(raw)


def pins():return json.loads(read(HERE/'dependencies.json'))


def check_source(root):
    root=Path(root).resolve(strict=True)
    for name,row in pins()['files'].items():
        path=HERE/Path(name).name if name.startswith('scripts/ci/fish-done-generic16k/') else root/name
        need(not any(p.is_symlink() for p in (path,*path.parents)),'source alias refused')
        raw=read(path,2*1024**2)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source pin differs: '+name)


def load(root,name):
    row=pins()['files'][name];path=HERE/Path(name).name if name.startswith('scripts/ci/fish-done-generic16k/') else Path(root)/name;raw=read(path,2*1024**2)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source module pin differs')
    spec=importlib.util.spec_from_file_location('done16k_'+sha(name.encode())[:16],path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def mapping():
    raw=read(HERE/'payload-map.json');need(sha(raw)==MAP_SHA,'explicit source payload map differs')
    value=json.loads(raw);need(value['schema_version']==1 and set(value['products'])=={'cachy-asahi-fish-done'},'exact Done script product required')
    return value


def products(root):
    value=mapping()
    for row in [*[r for p in value['products'].values() for r in p['payload'].values()],*value['fixtures'].values()]:
        path=Path(root)/row['source']
        need(not any(p.is_symlink() for p in (path,*path.parents)),'payload source alias refused')
        raw=read(path)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'mapped source payload differs: '+row['source'])
    return value['products']


def aligned(data,generic):
    interpreter,needed,loads=generic.elf(data)
    need(loads and all(a>=16384 and (v-o)%16384==0 for v,o,_,a in loads),'ELF not 16K aligned')
    return interpreter,needed


def test_transport(receipt):
    value=receipt['test_transport'];files=receipt['files'];build=value['native_build'];row=build['command']
    need(value['kind']=='NATIVE_C_RECORDER_PREPARE_ONLY' and value['product_change']=='NONE' and
        value['original_fixture_execution']=='NOT_RUN_UNCHANGED_CAPTURED_ONLY' and value['original_case_bodies']==18 and
        value['transport_timeout']=='UNCHANGED_2S_TERM_1S_KILL' and value['adaptation']=='ONLY_PREPARE_RECORDER_SUBSTITUTED',
        'explicit adapted test transport scope required')
    for field,path in (('original_fixture_sha256','fixtures/done.py'),('adapted_fixture_sha256',ADAPTED),
        ('recorder_source_sha256',SOURCE),('adapter_sha256',ADAPTER),('recorder_binary_sha256',RECORDER)):
        need(value[field]==files[path]['sha256'] and re.fullmatch('[0-9a-f]{64}',value[field]),'test transport payload hash join differs')
    need(files[RECORDER]['mode']==0o755 and files[ADAPTED]['mode']==files[SOURCE]['mode']==files[ADAPTER]['mode']==0o644 and
        RECORDER in receipt['elf'],'native recorder ELF/modes required')
    need(build['status']=='BUILT_NATIVE_C_TEST_RECORDER' and type(build['compile_count']) is int and build['compile_count']==1 and build['architecture']=='aarch64' and
        build['source_commit']==receipt['source_commit'] and build['source_sha256']==files[SOURCE]['sha256'] and
        build['binary_sha256']==files[RECORDER]['sha256'] and build['deadline_seconds']==30 and build['output_cap']==131072 and
        row['argv']==COMPILE and row['exit']==row['expected_exit']==0 and row['natural_exit'] is True and row['group_absent'] is True and
        type(row['pid']) is int and row['pid']>0 and row['pgid']==row['pid'] and 0<=row['seconds']<=35 and
        row['stdout_bytes']==row['stderr_bytes']==0 and row['stdout_sha256']==row['stderr_sha256']==sha(b''),
        'one naturally retired bounded native recorder compile required')
    compiler=build['compiler']
    need(compiler['path']=='/usr/bin/cc' and compiler['resolved'].startswith('/usr/bin/') and
        type(compiler['bytes']) is int and 0<compiler['bytes']<=64*1024**2 and
        re.fullmatch('[0-9a-f]{64}',compiler['sha256']),'native compiler executable identity required')
    return value
