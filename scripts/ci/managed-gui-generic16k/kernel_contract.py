# SPDX-License-Identifier: MIT
"""Bound the exact diagnostic build receipt and actual boot profile; no actors."""
import hashlib
import json
from pathlib import Path
import re
import stat

PROFILE='MANAGED_GUI_GENERIC16K_DIAGNOSTIC_V1'
RELEASE='7.1.13-generic16k-managed-gui'
REVISION='94fb23346d522edf53722357c426a3e58030beea'
ARCHIVE='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'
HELPER_SHA='ccbead2912144c5aa4fcb3ce7af76b3c11f28fcde7987e5f32edb060ff7b0ee9'
FRAGMENT_SHA='88819f00ebef80e385ebdfae6cc101ef21145e0bbd6bb12532b0d41a85c16d28'
DIAGNOSTIC_SHA='66f276cbb02451fa77785eb211467906ecbeaffdad9606616eafddd3f4a8f42d'


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,cap=65536):
    path=Path(path);info=path.lstat();need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=cap,'ordinary bounded kernel input')
    raw=path.read_bytes();need(len(raw)==info.st_size,'kernel input changed');return raw


def validate(value):
    need(type(value) is dict and set(value)=={'schema_version','profile','release','architecture','page_size','source_revision',
        'archive_sha256','helper_sha256','fragment_sha256','diagnostic_fragment_sha256','Image','config','modules'} and
        type(value['schema_version']) is int and value['schema_version']==1 and value['profile']==PROFILE and value['release']==RELEASE and
        value['architecture']=='aarch64' and value['page_size']==16384 and value['source_revision']==REVISION and
        value['archive_sha256']==ARCHIVE and value['modules']=='DISABLED' and
        value['helper_sha256']==HELPER_SHA and value['fragment_sha256']==FRAGMENT_SHA and value['diagnostic_fragment_sha256']==DIAGNOSTIC_SHA,'exact diagnostic kernel identity required')
    for key in ('helper_sha256','fragment_sha256','diagnostic_fragment_sha256'):
        need(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}',value[key]),'kernel source binding differs')
    for key,cap in (('Image',256*1024**2),('config',262144)):
        row=value[key];need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and
            0<row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256']),'kernel file binding differs')
    return value


def from_receipt(receipt,helper,fragment,helper_sha,fragment_sha):
    need(receipt['status']=='BUILT_ONLY' and receipt['kernel_build']=='PASS' and receipt['profile']==PROFILE and
         receipt['derivation']==dict(base_helper_sha256='e94adb4474183feea30ce1e2949b55c03e4969eeb1addb4c36892e8664ba9aaa',
             base_fragment_sha256='6d91180b80138d2d8039efafaaa9ca31349baea22b90430cbb15e07bce02e8f6',
             workspace_scan='ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',accepted_profiles_modified=False) and
         receipt['source_commit']==REVISION and receipt['archive']['sha256']==ARCHIVE and receipt['archive']['bytes']==262965559 and
         receipt['boot_diagnostics'] is True and receipt['kernel_release']==RELEASE and receipt['module_policy']['CONFIG_MODULES']=='n' and
         receipt['helper']['sha256']==helper_sha and receipt['fragment']['sha256']==fragment_sha and
         receipt['diagnostic_fragment']['sha256']==sha(fragment+helper.DIAGNOSTIC_FRAGMENT.encode()),'completed exact diagnostic build required')
    image=Path(receipt['image']['path']);config=Path(receipt['config']['path'])
    raw=read(image,256*1024**2);cfg=read(config,262144)
    need(len(raw)==receipt['image']['bytes'] and sha(raw)==receipt['image']['sha256'] and sha(cfg)==receipt['config']['sha256'],
         'actual diagnostic Image/config differs')
    helper.config_check(config,True);need(helper.image_check(image)['header_page_size']==16384,'actual Image page geometry differs')
    value=dict(schema_version=1,profile=PROFILE,release=RELEASE,architecture='aarch64',page_size=16384,source_revision=REVISION,
        archive_sha256=ARCHIVE,helper_sha256=helper_sha,fragment_sha256=fragment_sha,
        diagnostic_fragment_sha256=receipt['diagnostic_fragment']['sha256'],Image=dict(bytes=len(raw),sha256=sha(raw)),
        config=dict(bytes=len(cfg),sha256=sha(cfg)),modules='DISABLED')
    return validate(value),image,config


def boot(events,profile_path):
    raw=read(profile_path);profile=validate(json.loads(raw));rows=[r for r in events if r.get('event')=='boot']
    need(len(rows)==1 and rows[0].get('architecture')=='aarch64' and rows[0].get('page_size')==16384 and
         rows[0].get('kernel')==RELEASE and rows[0].get('kernel_profile_sha256')==sha(raw),'actual16K boot/profile join absent')
    return profile
