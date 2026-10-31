# SPDX-License-Identifier: MIT
"""Separate experimental Setup5 consumer; the held587/600 selection is immutable."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/setup5-expanded600/'
SETUP='cachy-asahi-setup'
PAIR='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44'
PROBE='0bbf875369c816aab19945c3e4f63c9b1f0b61b0'
ARCHIVE='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'
INDEX='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d'
AFTER='d263a3ca9089c204603f2e12b80dc4f209ee6e636f10da940a514040b636db79'
BEFORE='2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
TRIAL='04fabc5702c8389b7b2a53f6ed6168cc45931f6628c158e7e74b073349327c35'
PHASES=('upgrade-setup5-600','real-generated-rc-600','same-version-setup5-600','rollback-setup3-600')
LD_PHASES=('baseline587','install600',*PHASES)
PUBLIC=['lifecycle.json','real-modules.json','integration-plan.json','accepted-setup5-index.json',
        'setup5-pair-a.pkg.tar.xz','setup5-pair-b.pkg.tar.xz','setup5-signature.sig','setup3-before.desc','setup3-after.desc']
PUBLIC += [prefix+phase+suffix for phase in LD_PHASES for prefix,suffix in [('ld-','.json'),('aux-','.bin')]]


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and
        not any(c in str(path) for c in ',\r\n\0') and not any(p.is_symlink() for p in (path,*path.parents)),
        'ordinary absolute input required');return path


def read(path,cap=4*1024**2):
    path=safe(Path(path).absolute());info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'bounded ordinary JSON required')
    def pairs(rows):
        value={}
        for key,child in rows:need(key not in value,'duplicate JSON key');value[key]=child
        return value
    return json.loads(path.read_bytes(),object_pairs_hook=pairs)


def checked(root,ref,cap=16*1024**2):
    need(type(ref) is dict and set(ref)=={'path','bytes','sha256'} and type(ref['path']) is str and
        not ref['path'].startswith('/') and all(p not in ('','.','..') for p in ref['path'].split('/')) and
        type(ref['bytes']) is int and 0<ref['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',ref['sha256']),
        'exact bounded byte reference required')
    path=safe(root/ref['path']);need(path.is_file() and path.stat().st_size==ref['bytes'] and sha(path)==ref['sha256'],
        'bound input differs: '+ref['path']);return path


def ref(path,name=None):return dict(path=name or path.name,bytes=path.stat().st_size,sha256=sha(path))


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


def revision(root):return subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True,timeout=15).strip()


def policy():
    value=read(HERE/'input-policy.json')
    need(value.get('schema_version')==1 and value.get('status')=='ROOT_BOUND_SETUP5_EXPANDED600_AFTER_NATIVE600_ACCEPTANCE',
        'Root accepted original600 receipt and final bindings required before actors')
    need(re.fullmatch('[0-9a-f]{40}',value.get('baseline_source') or '') and value.get('setup5_source')==PAIR and
        value.get('probe_source')==PROBE and value.get('expected600_sha256')==AFTER,'held baseline/pair/probe identities differ')
    baseline=read(checked(HERE,value['baseline_acceptance']))
    need(baseline.get('status')=='ROOT_ACCEPTED_NATIVE_EXPANDED600_COMPOSITION' and baseline.get('source_sha')==value['baseline_source'] and
        re.fullmatch('[0-9]+',str(baseline.get('run_id',''))) and baseline.get('package_count')==600 and
        baseline.get('expected600_sha256')==AFTER and baseline.get('bang_version')=='0.1.0-2' and
        all(baseline.get(k)=='PASS' for k in ('bang_pair_bytes_buildinfo','installed_lifecycle','installed_six_modules','cleanup')) and
        baseline.get('hardware')=='NOT_RUN','original full600 native acceptance is absent/failed')
    proof=read(checked(HERE,value['setup5_acceptance']))
    need(proof.get('status')=='ROOT_ACCEPTED_NATIVE_SETUP5_LEGACY_AND_REAL_MODULES' and proof.get('run_id')==38946664234 and
        proof.get('source_sha')==PROBE and proof.get('real_cases')==6 and proof.get('legacy_events')==8 and
        proof.get('legacy_observations')==24 and proof.get('ordered_cleanup')=='PASS' and proof.get('hardware')=='NOT_RUN',
        'accepted Setup5 real-RC prerequisite differs')
    return value


def source(root):
    manifest=read(HERE/'source-manifest.json');need(manifest.get('schema_version')==1 and len(manifest.get('files',{}))>=8,
        'Root source freeze required')
    for name,row in manifest['files'].items():checked(root,dict(path=name,**row))
    return manifest


def expected(after,version):
    need(type(after) is dict and len(after)==600 and after.get(SETUP)=='0.1.0-3' and
        hashlib.sha256(''.join(n+' '+v+'\n' for n,v in sorted(after.items())).encode()).hexdigest()==AFTER,
        'exact held Setup3/full600 selection required')
    need(version in ('0.1.0-3','0.1.0-5'),'only explicit Setup3/5 trial versions allowed')
    return after|{SETUP:version}


def validate(result,native):
    need(result.get('status')=='PASS_SETUP5_EXPANDED600_INTEGRATION' and result.get('scope')=='SEPARATE_OWNED_FULL600_SETUP5_CONSUMER' and
        result.get('package_count')==result.get('restored_count')==600 and result.get('baseline600_sha256')==AFTER and
        result.get('setup5_archive_sha256')==ARCHIVE and result.get('setup3_version')=='0.1.0-3' and
        result.get('setup5_version')=='0.1.0-5' and result.get('original_consumer_modified') is False and
        result.get('hardware')=='NOT_RUN' and result.get('release')=='NOT_ADMITTED','separate complete600 integration result required')
    need([e.get('phase') for e in result.get('setup5_events',[])]==list(PHASES) and
        all(e.get('count')==600 and e.get('status')=='PASS' and
            all(e.get(k) is True for k in ('other599_versions','other599_database','other599_payload','configuration_preserved','database_check'))
            for e in result['setup5_events']) and
        all(e.get('inventory_sha256')==(AFTER if e['phase']==PHASES[-1] else TRIAL) for e in result['setup5_events']),
        'strict four-stage600 preservation required')
    need([(e.get('phase'),e.get('count')) for e in result.get('events',[])]==[('baseline587',587),('install600',600)] and
        all(e.get('status')=='PASS' and all(e.get(k) is True for k in ('signatures','dependencies','payload','ownership','originals_preserved','user_config_preserved')) for e in result['events']),'original bootstrap587/600 proof required')
    need([e.get('phase') for e in result.get('ldconfig',[])]==list(LD_PHASES) and
        all(e.get('helper_exit')=='NOT_OBSERVED' and e.get('transition',{}).get('kind') in
            (('BASELINE',) if index==0 else ('RAW_EQUAL','EXACT_LOAD_SAVE_ORDER')) and
            all(re.fullmatch('[0-9a-f]{64}',e.get(k) or '') for k in ('state_sha256','aux_sha256'))
            for index,e in enumerate(result['ldconfig'])),
        'separate exact ldconfig checkpoints required')
    native.validate_real(result['real_modules'])
    need(all(result.get(k) is True for k in ('complete_user_workspace_preserved','ordinary_user_processes_absent',
        'setup3_payload_restored','setup3_database_semantics_restored','other_setup3_db_files_identical')),
        'complete generated/edited workspace and exact Setup3 rollback proof required')
