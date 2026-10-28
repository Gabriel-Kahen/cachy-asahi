# SPDX-License-Identifier: MIT
"""Strict installed-prefix matching plus explicit TEST ALPM DATA, never release trust."""
import argparse
import base64
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from installed_reader_v1 import validate as prefix_validate, installed_result
from common import load, need, pin
from capsule import open_capsule
from installed_alpm_v1 import strict_signature



def manifest_files(view):return view.load('artifacts.json')['files']


def validate_native_pair(view,receipt,map_hash):
    pair=view.load('journey/pair-v1/result.json');files=manifest_files(view)
    need(receipt.get('native_pair')==pair and pair.get('status')=='PASS_REAL_NATIVE_DEVELOPER_PAIR_V1'
         and pair.get('source_map_sha256')==map_hash and pair.get('epoch')=='1791748800'
         and pair.get('builddir')=='/tmp/developer-pair-build'
         and pair.get('independent_clean_recipe_roots') is True and pair.get('recreated_builddir_each_time') is True
         and pair.get('inventory_before')==pair.get('inventory_after')==receipt['before_inventory']
         and pair.get('comparison')=='EXACT_ARCHIVE_PAYLOAD_PKGINFO_BUILDINFO','actual exact clean native pair required')
    rows=pair.get('builds');need(type(rows) is list and len(rows)==2,'exactly two actual builds required')
    need([row['directory'] for row in rows]==['/tmp/developer-pair-one','/tmp/developer-pair-two']
         and rows[0]['archive']==rows[1]['archive']==receipt['package']
         and rows[0]['payload']==rows[1]['payload'] and rows[0]['payload']
         and rows[0]['PKGINFO']==rows[1]['PKGINFO'] and rows[0]['BUILDINFO']==rows[1]['BUILDINFO'],'exact archive/payload/PKGINFO/BUILDINFO pair equality')
    for row in rows:
        for meta in ('PKGINFO','BUILDINFO'):
            need(row[meta]=={k:row['payload']['.'+meta][k] for k in ('bytes','sha256')},'pair metadata pins must join actual archive member map')
    commands=pair.get('commands');need(type(commands) is list and len(commands)==2
         and view.load('journey/pair-v1/commands.json')==commands,'two actual makepkg command originals required')
    for number,row in enumerate(commands,1):
        state=row['supervision'];name='journey/pair-v1/'+row['log']
        need(row['step']=='native-makepkg-'+str(number) and row['cwd']==rows[number-1]['directory']
             and row['argv']==['/usr/bin/makepkg','--nodeps','--nocheck','--nosign','--noconfirm','--config','/opt/native-developer-installed-v1/makepkg.conf']
             and row['success'] is True and name in files and pin(view.read(name))==row['log_pin']
             and state['reaped'] is True and state['ownership']=='REAPED' and state['group_census']=='EMPTY_TWICE'
             and state['output_complete'] is True and not state['signals'] and not state['timeout'] and state['error'] is None,
             'actual native makepkg command custody and unchanged owned retirement required')
    return pair


def validate_preservation(receipt):
    need(receipt.get('protected_paths')==dict(home='/home/alarm',trust='/etc/pacman.d/gnupg',config='/etc/pacman.conf')
         and receipt.get('protected_state_restored') is True
         and type(receipt.get('protected_before')) is dict
         and set(receipt['protected_before'])=={'home','trust','config'}
         and receipt['protected_before']==receipt.get('protected_after'), 'exact actual home/trust/config restoration required')
    for name in ('home','trust'):
        state=receipt['protected_before'][name]
        need(set(state)=={'root','entries'} and set(state['root'])=={'mode','uid','gid'}
             and type(state['entries']) is dict and len(state['entries'])<=4096,'complete protected directory metadata required')


def validate(capsule,binding):
    result=prefix_validate(capsule,binding)
    if result.get('status') in {'VALIDATED_NATIVE_FAILURE_SAFE_DIAGNOSTIC_DATA_ONLY','VALIDATED_INPUT_PROVISIONING_DIAGNOSTIC_NOT_NATIVE','VALIDATED_NATIVE_FAILURE_DATA_ONLY'}:
        need(result.get('native') in ('NOT_RUN','NOT_ADMITTED'),'failure DATA cannot grant native credit');return result
    need(result['status']=='VALIDATED_INSTALLED_COMPONENT_DATA_ONLY','all held prefix/daemon/retirement gates required')
    view=open_capsule(capsule);guest=view.load('journey/result.json');receipt=view.load('journey/alpm-v1/result.json')
    need(guest.get('test_alpm')==receipt and guest.get('alpm_installed') is True,
         'actual installed-time guest and ALPM originals must agree')
    need(receipt.get('status')=='PASS_TEST_SIGNED_ALPM_LIFECYCLE_V1' and receipt.get('source_map_sha256')==binding['map_sha256']
         and receipt.get('purpose')=='TEST_ONLY_DISPOSABLE_NATIVE_IMAGE_ALPM_V1'
         and receipt.get('signature_semantics')=='Required/Required'
         and receipt.get('trust_context')=='ONLY_EXPLICIT_TEST_PUBLIC_PRIMARY'
         and receipt.get('installed_count')==355 and receipt.get('restored_count')==354
         and all(receipt.get(k) is True for k in ('package_owned_paths_absent','user_data_preserved','test_homes_retired',
             'global_trust_unchanged','global_config_unchanged','private_test_directory_absent','official_home_retired')),
         'exact TEST trust/install/remove/user/dependency/cleanup outcomes required')
    usr=view.load('journey/usr-result.json')
    need(guest.get('usr_journey')==usr and usr.get('alpm_installed') is True,'original /usr and moved journey aggregate join')
    installed_result(view,manifest_files(view),usr,result['binding'],alias='usr-',expected_prefix=Path('/usr'))
    validate_native_pair(view,receipt,binding['map_sha256'])
    validate_preservation(receipt)
    strict_signature(receipt['signature_status'],receipt['fingerprint'])
    need(receipt.get('git_inputs',{}).get('status')=='PASS_EXACT_FIVE_ORIGINAL_SIGNED_GIT_INPUTS','real original-signed Git inputs required')
    public=receipt['public_key'];signature=receipt['signature']
    need(len(public['text'])<=16384 and public['text'].startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----')
         and 'PRIVATE KEY' not in public['text'] and pin(public['text'].encode('ascii'))=={k:public[k] for k in ('bytes','sha256')},'bounded original TEST public key DATA')
    need(len(signature['base64'])<=16384 and pin(base64.b64decode(signature['base64'],validate=True))=={k:signature[k] for k in ('bytes','sha256')},'bounded original detached signature DATA')
    need(receipt.get('alpm_runtime',{}).get('runtime')=='/usr/lib/cachy-asahi-developer-tools/0.1.0'
         and receipt['alpm_runtime'].get('status')=='PASS_PACKAGED_RUNTIME','actual ALPM-installed launcher/runtime proof')
    need(receipt['package']==guest['installed_package']['archive'] and receipt.get('user_before')==receipt.get('user_after')
         and set(receipt['user_before'])=={'keep.txt'},'built/installed package and user-state join required')
    from installed_alpm_v1 import git_policy,official_signature
    git,_=git_policy(Path(__file__).resolve().parents[1]);official=receipt['git_inputs']
    need(official['signer']==git['signer_fingerprint'] and official['files']==git['leaves'] and set(official['statuses'])=={r['filename'] for r in git['rows']},'exact five official Git signature/input joins')
    for status in official['statuses'].values():official_signature(status,git['signer_fingerprint'])
    manifest=view.load('artifacts.json')['files'];steps=[]
    for row in receipt['commands']:
        name='journey/alpm-v1/'+row['log'];state=row['supervision'];steps.append(row['step'])
        need(name in manifest and pin(view.read(name))==row['log_pin'] and row['success'] is True
             and state['reaped'] is True and state['ownership']=='REAPED' and state['group_census']=='EMPTY_TWICE'
             and state['output_complete'] is True and not state['signals'] and not state['timeout'] and state['error'] is None,
             'actual ALPM/GPG command raw DATA and owned retirement required')
        raw=view.read(name)
        if row['step'].startswith('git-official-'):
            selected=next(r for r in git['rows'] if 'git-official-'+r['name']==row['step']);need(raw.decode()==official['statuses'][selected['filename']],'actual original Git signature bytes differ')
        if row['step']=='verify-exact-test-signature':need(raw==receipt['signature_status'].encode(),'actual signature status bytes differ')
        if row['step']=='untrusted-test-signature-control':need(b'NO_PUBKEY' in raw and row['expected']=='nonzero','untrusted-key negative control required')
        if row['step']=='trust-key-membership':need([line.split(':')[9] for line in raw.decode().splitlines() if line.startswith('fpr:')]==[receipt['fingerprint']],'only explicit TEST primary in trust context')
        if row['step'] in ('baseline-inventory','removed-inventory','installed-inventory'):
            from installed_alpm_v1 import git_policy
            _,base=git_policy(Path(__file__).resolve().parents[1])
            wanted=b''.join(sorted(base.splitlines(keepends=True)+[b'cachy-asahi-developer-tools 0.1.0-1\n'])) if row['step']=='installed-inventory' else base
            need(b''.join(sorted(raw.splitlines(keepends=True)))==wanted,'actual complete dependency inventory differs')
    order=['generate-test-key','untrusted-test-signature-control','import-only-test-public','verify-exact-test-signature',
           'required-signature-install','usr-installed-user-journeys','installed-user-journeys','required-policy-remove','removed-inventory']
    need(all(s in steps for s in order) and [steps.index(s) for s in order]==sorted(steps.index(s) for s in order),
         'strict ordered actual lifecycle required')
    return dict(status='VALIDATED_TEST_SIGNED_INSTALLED_COMPONENT_EVIDENCE_ONLY',binding=result['binding'],
        TEST_trust='DISPOSABLE_IMAGE_ONLY',actual_execution_scope=receipt['execution_scope'],
        missing={},native='NOT_ADMITTED',native_16K='NOT_QUALIFIED',physical_M2='NOT_RUN',release='NOT_ADMITTED')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--capsule',type=Path,required=True);parser.add_argument('--binding',type=Path,required=True);args=parser.parse_args()
    print(json.dumps(validate(args.capsule,load(args.binding)),sort_keys=True))
