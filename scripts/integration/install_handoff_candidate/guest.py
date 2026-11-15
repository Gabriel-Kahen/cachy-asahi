#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""TEST-signed host-x86 container install/reinstall/remove; no native admission."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import time

HERE = Path(__file__).resolve().parent


def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


L = load('unchanged_finite_lifecycle',HERE/'lifecycle.py')
C = load('candidate_controls',HERE/'controls.py')
PRIVATE = Path('/usr/lib/cachy-asahi/install-handoff')
CLI = '/usr/bin/cachy-asahi-install-handoff'
DRIVER = '''import importlib.util,pathlib,sys
root=pathlib.Path(sys.argv[1])
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
runtime=load('TEST_installed_runtime',root/'scripts/install/fresh_handoff/runtime.py')
lock=runtime.verify(root,sys.argv[2])
handoff=load('TEST_installed_handoff',root/'scripts/install/fresh_handoff/handoff.py')
handoff.DELIVERED_SOURCE_LOCK=lock
# TEST-only explicit anchor. All installed verifier bodies remain unchanged.
handoff.R.P.auth.KEYS={**handoff.R.P.auth.KEYS,'alarm':(sys.argv[3],sys.argv[4])}
raise SystemExit(handoff.main(sys.argv[5:]))
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def snapshot(root):
    if not root.exists():
        return {}
    result = {}
    total = 0
    for path in root.rglob('*'):
        item = path.lstat()
        name = path.relative_to(root).as_posix()
        if stat.S_ISLNK(item.st_mode):
            result[name] = dict(kind='symlink',target=os.readlink(path))
        elif stat.S_ISREG(item.st_mode):
            total += item.st_size
            L.require(total <= 32*1024**2,'snapshot byte bound')
            result[name] = dict(kind='file',sha256=sha(path.read_bytes()),bytes=item.st_size,
                                mode=stat.S_IMODE(item.st_mode),uid=item.st_uid,gid=item.st_gid)
        else:
            L.require(stat.S_ISDIR(item.st_mode),'unexpected caller node')
        L.require(len(result) <= 4096,'snapshot node bound')
    return result


def execute(contract_pin):
    raw = Path('/inputs/contract.json').read_bytes()
    L.require(len(raw) <= 2*1024**2 and sha(raw) == contract_pin,'external contract differs')
    contract = C.validate_contract(L.strict_json(raw.decode()))
    end = time.monotonic()+300
    report = dict(status='RUNNING',execution=contract['execution'],image_id=contract['image_id'],
                  package_sha256=contract['package']['sha256'],checks=[],commands=[],
                  native_arm='NOT RUN',generic_arm_16k='NOT RUN',M2='NOT RUN',release_accepted=False,
                  hooks='DISABLED_BY_PRIVATE_MASKS; package ships no hooks',trust='EPHEMERAL_TEST_ONLY')
    def guard():
        raw_mounts = Path('/proc/self/mountinfo').read_text()
        destinations = [row.split()[4] for row in raw_mounts.splitlines()]
        L.require(len(destinations) == len(set(destinations)),'duplicate mount destination')
        facts = L.actual_environment()
        facts['standard_devices'] = {}
        for name in ('null','zero','full','random','urandom','tty'):
            path = Path('/dev')/name
            node = path.lstat()
            facts['standard_devices'][str(path)] = dict(symlink=stat.S_ISLNK(node.st_mode),
                kind='char' if stat.S_ISCHR(node.st_mode) else 'other',
                device=[os.major(node.st_rdev),os.minor(node.st_rdev)] if stat.S_ISCHR(node.st_mode) else None)
        C.guard(facts,contract)
        L.require(time.monotonic() < end,'overall guest deadline')
        return facts
    facts = guard()
    for name,pin in contract['source_files'].items():
        L.require(sha((HERE/name).read_bytes()) == pin,'runner source differs: '+name)
    L.require(Path('/out').is_dir() and not any(Path('/out').iterdir()),'fresh evidence output required')
    L.require(Path(__file__).resolve() == Path('/runner/guest.py'),'fixed mounted runner path required')
    report['environment'] = facts
    def save():
        Path('/out/report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    def check(label,ok):
        report['checks'].append(dict(check=label,status='PASS' if ok else 'FAIL'))
        save()
        L.require(ok,'check failed: '+label)
    def command(label,argv,expected=0,stdin=None):
        guard()
        result = L.bounded_process(argv,timeout=min(90,end-time.monotonic()),stdout_limit=2*1024**2,
                                   stderr_limit=1024**2,stdin=stdin,
                                   env=dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',HOME='/tmp',
                                            PYTHONPATH='/TEST-poison',PYTHONHOME='/TEST-poison'))
        sequence = len(report['commands'])
        body = {key:(value.decode('utf-8','replace') if isinstance(value,bytes) else value) for key,value in result.items()}
        body.update(label=label,argv=list(map(str,argv)),expected_returncode=expected)
        Path('/out/'+str(sequence).zfill(3)+'.json').write_text(json.dumps(body,indent=2,sort_keys=True)+'\n')
        report['commands'].append(dict(label=label,returncode=result['returncode'],reason=result['reason'],cleanup=result['cleanup']))
        save()
        L.require(result['reason'] == 'exit' and result['returncode'] == expected and
                  result['cleanup'].get('reaped') is True and not result['cleanup'].get('errors'),
                  'command refused: '+label+': '+result['stderr'].decode('utf-8','replace')[-2000:])
        return result['stdout']
    def inventory(label):
        raw = command(label,['/usr/bin/pacman','-Q'])
        rows = dict(line.split(' ',1) for line in raw.decode().splitlines())
        report.setdefault('inventories',{})[label] = rows
        save()
        return rows
    def payload(label,present=True):
        observed = {}
        for name,row in contract['payload'].items():
            path = Path('/')/name
            if present:
                item = path.lstat()
                L.require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and item.st_uid == item.st_gid == 0,
                          'installed file type/ownership differs: '+name)
                observed[name] = dict(bytes=item.st_size,sha256=sha(path.read_bytes()),mode=stat.S_IMODE(item.st_mode))
            else:
                observed[name] = dict(exists=path.exists(),symlink=path.is_symlink())
                L.require(observed[name] == dict(exists=False,symlink=False),'package-owned leaf survives removal: '+name)
        check(label,not present or observed == contract['payload'])
        if present:
            report.setdefault('payloads',{})[label] = observed
            save()
        else:
            report['removed_owned_leaves'] = observed
            save()
    try:
        package = Path('/inputs/package.pkg.tar.zst')
        public = Path('/inputs/TEST-public.asc')
        signature = Path(str(package)+'.sig')
        check('exact-package-and-public-signature-inputs',package.stat().st_size == contract['package']['bytes'] and
              sha(package.read_bytes()) == contract['package']['sha256'] and
              signature.stat().st_size == contract['package']['signature_bytes'] and
              sha(signature.read_bytes()) == contract['package']['signature_sha256'] and
              public.stat().st_size == contract['signer']['certificate_bytes'] and
              sha(public.read_bytes()) == contract['signer']['certificate_sha256'])
        check('public-export-not-secret',public.read_bytes().startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and
              b'PRIVATE KEY' not in public.read_bytes())
        baseline = inventory('baseline')
        check('candidate-absent-before-install','cachy-asahi-install-handoff' not in baseline)
        standard_keyring = snapshot(Path('/etc/pacman.d/gnupg'))
        original_config = Path('/etc/pacman.conf').read_bytes()
        command('existing-dependencies',['/usr/bin/pacman','-T','python>=3.11','gnupg','pacman','coreutils','libarchive','bash'])
        keyring = Path('/tmp/handoff-test-keyring-'+contract['nonce'])
        keyring.mkdir(mode=0o700)
        gpg = ['/usr/bin/gpg','--no-options','--batch','--homedir',str(keyring),'--no-auto-key-retrieve']
        command('import-TEST-public',gpg+['--import',str(public)])
        listing = command('pin-TEST-primary',gpg+['--with-colons','--fingerprint','--list-keys']).decode()
        fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        check('one-exact-TEST-public-primary',fingerprints == [contract['signer']['fingerprint']])
        command('private-TEST-ownertrust',gpg+['--import-ownertrust'],stdin=contract['signer']['fingerprint']+':6:\n')
        command('private-TEST-trustdb',gpg+['--check-trustdb'])
        command('verify-exact-package-signature',gpg+['--status-fd','1','--verify',str(signature),str(package)])
        hooks = Path('/builder-disabled-hooks')
        hooks.mkdir(mode=0o700,exist_ok=False)
        for directory in (Path('/usr/share/libalpm/hooks'),Path('/etc/pacman.d/hooks')):
            for path in directory.glob('*.hook'):
                if not (hooks/path.name).exists() and not (hooks/path.name).is_symlink():
                    (hooks/path.name).symlink_to('/dev/null')
        config = ('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\n'
                  'LocalFileSigLevel = Required TrustedOnly\nGPGDir = '+str(keyring)+'\nHookDir = /builder-disabled-hooks\n')
        check('exact-offline-strict-pacman-config',Path('/inputs/pacman.conf').read_text() == config)
        pacman = ['/usr/bin/pacman','--config','/inputs/pacman.conf']
        unsigned = Path('/tmp/unsigned.pkg.tar.zst')
        shutil.copyfile(package,unsigned)
        command('missing-package-signature-refused',pacman+['-U','--noconfirm','--noscriptlet',str(unsigned)],expected=1)
        check('missing-signature-preserves-baseline',inventory('after-refusal') == baseline)
        command('signed-install',pacman+['-U','--noconfirm','--noscriptlet',str(package)])
        expected = {**baseline,'cachy-asahi-install-handoff':'0.1.0-1'}
        check('install-inventory-only-candidate',inventory('installed') == expected)
        payload('installed-exact39')
        command('installed-pacman-Qk',['/usr/bin/pacman','-Qk','cachy-asahi-install-handoff'])
        caller = Path('/var/tmp/install-handoff-caller-'+contract['nonce'])
        caller.mkdir(mode=0o700)
        shutil.copytree('/inputs/handoff',caller/'handoff',symlinks=True)
        (caller/'state').mkdir(mode=0o700)
        (caller/'operator-note.txt').write_bytes(b'TEST caller data survives package removal\n')
        caller_before = snapshot(caller)
        report['caller_snapshots'] = dict(before=caller_before)
        check('caller-copies-match-input-pins',all(sha((caller/'handoff'/name).read_bytes()) == pin
              for name,pin in contract['handoff']['files'].items()))
        check('producer-sources-and-private-key-not-mounted',set(path.name for path in HERE.iterdir()) == set(contract['source_files']) and
              not Path('/inputs/checks').exists() and not Path('/inputs/private').exists() and
              not Path('/work/scripts/install/fresh_handoff/handoff.py').exists() and
              not Path('/work/packages/tools/cachy-asahi-install-handoff').exists())
        driver = Path('/tmp/TEST-explicit-anchor-driver.py')
        driver.write_text(DRIVER)
        arguments = ['verify','--workspace',str(caller/'handoff'),'--receipt-sha256',contract['handoff']['receipt_sha256'],
                     '--selection-sha256',contract['handoff']['selection_sha256'],'--state-dir',str(caller/'state')]
        def cli_phase(label,private,cli):
            command(label+'-help',[str(cli),'--runtime-sha256',contract['handoff']['runtime_sha256'],'--','--help'])
            # Product command must retain the genuine fixed-ALARM TEST refusal.
            before = len(report['commands'])
            command(label+'-production-TEST-trust-refusal',[str(cli),'--runtime-sha256',contract['handoff']['runtime_sha256'],'--',*arguments],expected=1)
            body = json.loads(Path('/out/'+str(before).zfill(3)+'.json').read_bytes())
            check(label+'-named-production-refusal','PREDECESSOR_AUTH_REFUSED' in body['stderr'] and 'pinned ALARM certificate required' in body['stderr'])
            data = command(label+'-explicit-TEST-anchor-verification',['/usr/bin/python3','-I','-B',str(driver),str(private),
                contract['handoff']['runtime_sha256'],contract['handoff']['archive_certificate_fingerprint'],
                contract['handoff']['archive_certificate_sha256'],*arguments])
            result = json.loads(data)
            check(label+'-genuine-TEST-crypto',result['status'] == 'HELD_DEVELOPMENT_HANDOFF' and
                  result['fresh_recovery_signature_verification'] is True and not result['release_accepted'])
            observed = snapshot(caller)
            report['caller_snapshots'][label] = observed
            check(label+'-caller-data-unchanged',observed == caller_before)
        cli_phase('installed',PRIVATE,Path(CLI))
        moved = Path('/var/tmp/moved-handoff-prefix-'+contract['nonce'])
        for name in contract['payload']:
            target = moved/name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(Path('/')/name,target)
        cli_phase('moved',moved/'usr/lib/cachy-asahi/install-handoff',moved/'usr/bin/cachy-asahi-install-handoff')
        moved_before = snapshot(moved)
        command('signed-same-version-reinstall',pacman+['-U','--noconfirm','--noscriptlet',str(package)])
        check('reinstall-inventory-only-candidate',inventory('reinstalled') == expected)
        payload('reinstalled-exact39')
        cli_phase('reinstalled',PRIVATE,Path(CLI))
        command('signed-package-removal',pacman+['-R','--noconfirm','--noscriptlet','cachy-asahi-install-handoff'])
        check('removal-restores-complete-baseline',inventory('removed') == baseline)
        payload('all39-owned-leaves-removed',present=False)
        observed = snapshot(caller)
        report['caller_snapshots']['removed'] = observed
        check('caller-handoff-recovery-state-survive-removal',observed == caller_before)
        check('unowned-moved-prefix-survives-removal',snapshot(moved) == moved_before)
        cli_phase('moved-after-removal',moved/'usr/lib/cachy-asahi/install-handoff',moved/'usr/bin/cachy-asahi-install-handoff')
        observed_keyring = snapshot(Path('/etc/pacman.d/gnupg'))
        observed_config = Path('/etc/pacman.conf').read_bytes()
        report['system_keyring_snapshots'] = dict(before=standard_keyring,after=observed_keyring)
        report['system_config_sha256'] = dict(before=sha(original_config),after=sha(observed_config))
        check('original-config-and-keyring-preserved',observed_config == original_config and observed_keyring == standard_keyring)
        command('stop-private-public-keyring-agent',['/usr/bin/gpgconf','--homedir',str(keyring),'--kill','all'])
        shutil.rmtree(keyring)
        check('private-TEST-keyring-cleaned',not keyring.exists())
        report.update(status='PASS_HOST_X86_INSTALLED_LIFECYCLE_ONLY',package_transactions=3,
                      missing_signature_refusals=1,installed_file_count=39,producer_sources='NOT_MOUNTED',
                      TEST_anchor='Explicit driver only; unchanged production launcher refuses TEST certificate',
                      caller_snapshot=caller_before,lifecycle_source_sha256=contract['source_files']['lifecycle.py'])
        return report
    except BaseException as error:
        report.update(status='FAIL',error=str(error))
        raise
    finally:
        save()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract-sha256',required=True)
    args = parser.parse_args()
    print(json.dumps(execute(args.contract_sha256),sort_keys=True))
