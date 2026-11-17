#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Generate/verify a finite offline PROJECT TEST layer; never run actors here."""
import importlib.util
import json
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location('libgit2_project_test', Path(__file__).with_name('project_test.py'))
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)
LABEL = 'org.cachy-asahi.libgit2-reference.nonce'
KEYRING = '/project-test-gnupg'
EXPECTED349 = {'bytes': 6800, 'sha256': '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'}


def expected350(raw349):
    """Preserve every signed349 row/version and add only the original llhttp."""
    P.need(type(raw349) is bytes and len(raw349) <= 65536 and raw349.endswith(b'\n'), 'bounded whole signed349 inventory')
    rows = raw349.decode('ascii').splitlines()
    parsed = [r.split(' ') for r in rows]
    P.need(len(rows) == 349 and all(len(r) == 2 and re.fullmatch(r'[a-z0-9@+_.-]+', r[0])
           and r[1] and not any(c.isspace() for c in r[1]) for r in parsed), 'exact ordinary349 package/version inventory')
    names = [r[0] for r in parsed]
    P.need(len(set(names)) == 349 and rows == sorted(rows) and not {'llhttp', P.DEFAULT_EXPECTED['package']} & set(names),
           'unchanged unique signed349 without substituted llhttp provider')
    return ('\n'.join(sorted(rows + [P.DEFAULT_EXPECTED['package'] + ' ' + P.DEFAULT_EXPECTED['version']])) + '\n').encode('ascii')


# This is inert source DATA until the Root-admitted, supervised Docker build.
# Every executable is an existing qualified binary inside the signed349 image.
INSTALLER = r'''import hashlib,json,os,pathlib,stat,subprocess
R=pathlib.Path('/project-test-input');K='/project-test-gnupg'
M=json.loads((R/'manifest.json').read_bytes())
def need(v,s):
    if not v:raise ValueError(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def run(a):
    p=subprocess.run(a,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=90,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':K})
    need(len(p.stdout)<=16777216 and len(p.stderr)<=1048576 and p.returncode==0,'checked bounded dependency actor: '+a[0]);return p.stdout
def custody(paths):
    rows=[];total=0
    need(len(paths)<=100000,'bounded full349 provider path count')
    for name in sorted(paths):
        p=pathlib.Path(name);s=p.lstat();row=[name,s.st_mode&4095,s.st_uid,s.st_gid]
        if stat.S_ISLNK(s.st_mode):row+=['link',os.readlink(p)]
        elif stat.S_ISREG(s.st_mode):
            need(s.st_size<=536870912,'bounded provider file');total+=s.st_size;need(total<=8589934592,'bounded full349 provider bytes')
            h=hashlib.sha256();seen=0
            with p.open('rb') as f:
                while True:
                    b=f.read(1048576)
                    if not b:break
                    seen+=len(b);need(seen<=s.st_size,'stable bounded provider file');h.update(b)
            t=p.lstat();need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns) and seen==s.st_size,'stable complete provider bytes')
            row+=['file',seen,h.hexdigest()]
        else:need(stat.S_ISDIR(s.st_mode),'ordinary provider path');row+=['dir']
        rows.append(row)
    return {'paths':len(rows),'payload_bytes':total,'sha256':hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()}
def tree():
    rows=[];root=pathlib.Path('/etc/pacman.d/gnupg')
    for p in sorted(root.rglob('*')):
        s=p.lstat();name=str(p.relative_to(root))
        if p.is_symlink():rows.append([name,'link',os.readlink(p)])
        elif p.is_file():rows.append([name,'file',s.st_mode&4095,pin(p.read_bytes())])
        else:need(p.is_dir(),'ordinary unchanged official keyring');rows.append([name,'dir',s.st_mode&4095])
    need(rows,'existing official349 trust required');return pin(json.dumps(rows,sort_keys=True,separators=(',',':')).encode())
for name,want in M['copies'].items():need(pin((R/name).read_bytes())==want,'exact dependency context copy '+name)
before=run(['/usr/bin/pacman','-Q']);before=b'\n'.join(sorted(before.splitlines()))+b'\n'
need(pin(before)==M['expected349'],'actual full signed349 inventory before transaction')
need(pathlib.Path('/builder-packages.lock').read_bytes()==before,'signed349 inventory receipt agrees')
trust=tree();pathlib.Path(K).mkdir(mode=448)
owned=set(run(['/usr/bin/pacman','-Qlq']).decode().splitlines())
need(all(x.startswith('/') and '..' not in pathlib.PurePosixPath(x).parts for x in owned),'absolute existing349 owned paths')
provider_before=custody(owned)
db=pathlib.Path('/var/lib/pacman/local');db_names={p.name for p in db.iterdir()}
need(len([p for p in db.iterdir() if p.is_dir()])==349,'complete349 existing local database')
db_paths={str(p) for p in db.rglob('*')};database_before=custody(db_paths)
g=['/usr/bin/gpg','--no-options','--batch','--no-tty','--no-autostart','--no-auto-key-retrieve','--auto-key-locate','clear','--homedir',K]
run(g+['--import',str(R/'public_key')])
keys=run(g+['--with-colons','--with-subkey-fingerprint','--fingerprint','--list-keys']).decode('ascii').splitlines()
primary=[];wanted=False
for line in keys:
    row=line.split(':')
    if row[0]=='pub':wanted=True;need(row[1] not in ('r','e','d'),'valid public TEST key')
    elif row[0]=='fpr' and wanted:primary.append(row[9]);wanted=False
need(primary==[M['fingerprint']],'one exact primary public PROJECT TEST key')
need(not any(x.startswith(('sec:','ssb:')) for x in run(g+['--with-colons','--list-secret-keys']).decode('ascii').splitlines()),'public PROJECT TEST key only; no secret keys')
test_fingerprints={x.split(':')[9] for x in keys if x.startswith('fpr:')}
official_fingerprints=set()
rings=[p for p in pathlib.Path('/etc/pacman.d/gnupg').iterdir() if p.name in ('pubring.gpg','pubring.kbx') and p.is_file()]
need(rings,'existing official349 public keyring')
for ring in rings:
    official=run(g+['--no-default-keyring','--keyring',str(ring),'--lock-never','--no-auto-check-trustdb','--with-colons','--with-subkey-fingerprint','--fingerprint','--list-keys']).decode('ascii')
    official_fingerprints.update(x.split(':')[9] for x in official.splitlines() if x.startswith('fpr:'))
need(official_fingerprints and test_fingerprints and not official_fingerprints.intersection(test_fingerprints),'PROJECT TEST key must be distinct from every official ALARM primary/subkey')
owner=R/'ownertrust';owner.write_text(M['fingerprint']+':6:\n')
run(g+['--import-ownertrust',str(owner)])
status=run(g+['--status-fd','1','--verify',str(R/M['signature']),str(R/M['package'])]).decode('utf-8')
lines=[x.split() for x in status.splitlines() if x.startswith('[GNUPG:] ')]
need(not any(x[1] in ('BADSIG','ERRSIG','EXPKEYSIG','EXPSIG','REVKEYSIG','NO_PUBKEY','KEYREVOKED') for x in lines),'no invalid signature/key status')
valid=[x[2:] for x in lines if x[1]=='VALIDSIG']
need(len(valid)==1 and len(valid[0]) in (9,10),'one actual cryptographically valid detached signature')
signer=valid[0][0];primary_fingerprint=valid[0][9] if len(valid[0])==10 else signer
need(primary_fingerprint==M['fingerprint'],'actual signature belongs to exact public PROJECT TEST key')
need(any(x[1] in ('TRUST_FULLY','TRUST_ULTIMATE') for x in lines),'explicit separate PROJECT TEST trust')
run(['/usr/bin/pacman','--config',str(R/'pacman-project-test.conf'),'--gpgdir',K,'-U','--noconfirm',str(R/M['package'])])
run(['/usr/bin/ldconfig'])
after=run(['/usr/bin/pacman','-Q']);after=b'\n'.join(sorted(after.splitlines()))+b'\n'
need(pin(after)==M['expected350'],'all349 providers unchanged; only pinned project llhttp added')
provider_after=custody(owned);need(provider_after==provider_before,'all349 existing package-owned paths and bytes unchanged')
need({p.name for p in db.iterdir()}==db_names|{'cachy-asahi-llhttp-reference-9.3.1-1'},'only exact project llhttp added to local package database')
database_after=custody(db_paths);need(database_after==database_before,'all349 original local package database bytes unchanged')
need(tree()==trust,'official349 pacman trust must remain byte-identical')
pathlib.Path('/builder-packages.lock').write_bytes(after)
e={'schema':1,'status':'PROJECT_TEST_DEPENDENCY_INSTALLED','test_only':True,'tuple_sha256':M['tuple_sha256'],'root_receipt':M['root_receipt'],'fingerprint':M['fingerprint'],'signer_fingerprint':signer,'primary_fingerprint':primary_fingerprint,'crypto':'GPG_VALIDSIG','trust_keyring':K,'official_key_overlap':False,'official_key_count':len(official_fingerprints),'test_key_fingerprints':sorted(test_fingerprints),'provider_before':provider_before,'provider_after':provider_after,'database_before':database_before,'database_after':database_after,'official_trust_before':trust,'official_trust_after':tree(),'inventory_before':pin(before),'inventory_after':pin(after),'package':M['copies'][M['package']],'signature':M['copies'][M['signature']],'public_key':M['copies']['public_key'],'transaction':['/usr/bin/pacman','--config',str(R/'pacman-project-test.conf'),'--gpgdir',K,'-U','--noconfirm',str(R/M['package'])]}
pathlib.Path('/project-test-evidence.json').write_text(json.dumps(e,sort_keys=True)+'\n')
# Keep public TEST trust first-class, but no signing or private key material.
owner.unlink()
'''


def prepare_context(metadata, paths, expected349_path, base_image, context, *, nonce, attempt='dependency'):
    """Write DATA only. Parent owns supervised Docker execution and cleanup.

    The caller supplies independently Root-admitted metadata. No TEST key ever
    enters the official keyring; no repository, APT or dependency bypass exists.
    """
    P.need(metadata.get('admitted') is True, 'unbound PROJECT TEST dependency cannot produce an executable plan')
    checked = P.validate_tuple(paths, metadata['expected'], metadata['Root_authorization'])
    P.need(checked == metadata, 'exact current Root-bound dependency metadata')
    P.need(re.fullmatch(r'sha256:[0-9a-f]{64}', base_image), 'immutable actual signed349 base image')
    P.need(re.fullmatch(r'[a-f0-9]{16,64}', nonce) and attempt == 'dependency', 'finite owned dependency image identity')
    raw349 = P.read(expected349_path, 65536)
    P.need(P.pin(raw349) == EXPECTED349, 'frozen original signed349 baseline bytes required')
    raw350 = expected350(raw349)
    context = Path(context).absolute()
    P.need(context.parent == context.parent.resolve() and not context.exists(), 'new ordinary dependency context only')
    context.mkdir(mode=0o700)
    package = P.DEFAULT_EXPECTED['filename'];signature = package + '.sig'
    copied = {}
    for key in P.KEYS:
        name = package if key == 'package' else signature if key == 'signature' else key
        raw = P.read(paths[key], 4*1024**2 if key == 'package' else 256*1024)
        P.need(P.pin(raw) == metadata['pins'][key], 'stable dependency copy custody')
        (context/name).write_bytes(raw);copied[name] = P.pin(raw)
    manifest = {'schema': 1, 'tuple_sha256': metadata['tuple_sha256'], 'fingerprint': metadata['fingerprint'],
                'root_receipt': metadata['pins']['root_receipt'], 'copies': copied, 'package': package,
                'signature': signature, 'expected349': P.pin(raw349), 'expected350': P.pin(raw350)}
    config = ('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
              'LocalFileSigLevel = Required TrustedOnly\nGPGDir = '+KEYRING+'\n'
              'HookDir = /builder-disabled-hooks\n')
    files = {'manifest.json': P.canonical(manifest), 'install-project-test.py': INSTALLER.encode(),
             'pacman-project-test.conf': config.encode(), 'expected349.lock': raw349, 'expected350.lock': raw350,
             '.dockerignore': b''}
    for name, raw in files.items():
        (context/name).write_bytes(raw)
    dockerfile = ('FROM '+base_image+'\nLABEL '+LABEL+'=""\nUSER root\nCOPY . /project-test-input/\n'
                  'RUN /usr/bin/python3 -I -B /project-test-input/install-project-test.py\nUSER alarm\nWORKDIR /tmp\n')
    (context/'Dockerfile').write_text(dockerfile)
    iid = context.parent/'project-test-image-id'
    tag = 'cachy-asahi-libgit2-project-test:' + nonce
    command = ['/usr/bin/docker', 'build', '--network=none', '--pull=false', '--platform=linux/arm64',
               '--memory=4294967296', '--memory-swap=4294967296', '--cpu-period=100000', '--cpu-quota=400000',
               '--iidfile', str(iid), '--quiet', '--label', LABEL+'='+nonce, '--tag', tag, str(context)]
    return {'schema': 1, 'status': 'ROOT_BOUND_DATA_PLAN_ONLY', 'tuple_sha256': metadata['tuple_sha256'],
            'base_image': base_image, 'context': str(context), 'iidfile': str(iid), 'tag': tag,
            'nonce': nonce, 'build_command': command, 'manifest': manifest, 'dockerfile': P.pin(dockerfile.encode()),
            'expected350_text': raw350.decode('ascii'), 'context_pins': {p.name: P.pin(p.read_bytes()) for p in sorted(context.iterdir())}}


def reader_arguments(image, nonce):
    """Finite read-only owned reader; caller supervises and removes its container."""
    P.need(re.fullmatch(r'sha256:[0-9a-f]{64}', image) and re.fullmatch(r'[a-f0-9]{16,64}', nonce), 'immutable image and nonce for dependency reader')
    code = "import json,pathlib;print(json.dumps({'inventory':pathlib.Path('/builder-packages.lock').read_text(),'evidence':json.loads(pathlib.Path('/project-test-evidence.json').read_text())},sort_keys=True))"
    return ['/usr/bin/docker', 'run', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory=268435456', '--memory-swap=268435456', '--cpus=1', '--pids-limit=32',
            '--label', LABEL+'='+nonce, '--name', 'libgit2-reference-'+nonce+'-dependency-reader',
            '--entrypoint', '/usr/bin/python3', image, '-I', '-B', '-c', code]


def verify_result(plan, image_id, inventory_raw, evidence_raw):
    """Check retained actual image evidence, without launching any actor."""
    P.need(re.fullmatch(r'sha256:[0-9a-f]{64}', image_id) and image_id != plan['base_image'], 'distinct immutable PROJECT TEST dependency image')
    P.need(type(inventory_raw) is bytes and len(inventory_raw) <= 65536, 'bounded complete dependency image inventory')
    P.need(type(evidence_raw) is bytes and len(evidence_raw) <= 65536, 'bounded complete dependency installation evidence')
    evidence = P.load(evidence_raw);manifest = plan['manifest']
    P.need(P.pin(inventory_raw) == manifest['expected350'] and inventory_raw.decode('ascii') == plan['expected350_text'], 'exact350 inventory with every signed349 provider unchanged')
    P.need(evidence.get('schema') == 1 and evidence.get('status') == 'PROJECT_TEST_DEPENDENCY_INSTALLED'
           and evidence.get('test_only') is True and evidence.get('tuple_sha256') == plan['tuple_sha256']
           and evidence.get('root_receipt') == manifest['root_receipt'], 'actual exact Root-bound PROJECT TEST installation receipt')
    P.need(evidence.get('crypto') == 'GPG_VALIDSIG' and evidence.get('fingerprint') == manifest['fingerprint']
           and evidence.get('primary_fingerprint') == manifest['fingerprint']
           and re.fullmatch(r'(?:[A-F0-9]{40}|[A-F0-9]{64})', evidence.get('signer_fingerprint', ''))
           and evidence.get('trust_keyring') == KEYRING, 'actual separate public TEST keyring/signature verification')
    P.need(evidence.get('official_trust_before') == evidence.get('official_trust_after')
           and type(evidence.get('official_trust_before')) is dict
           and re.fullmatch(r'[0-9a-f]{64}', evidence['official_trust_before'].get('sha256', '')),
           'official349 trust remains unchanged')
    P.need(evidence.get('inventory_before') == manifest['expected349'] and evidence.get('inventory_after') == manifest['expected350'], 'actual complete before/after provider inventory')
    P.need(evidence.get('official_key_overlap') is False and type(evidence.get('official_key_count')) is int
           and evidence['official_key_count'] > 0 and manifest['fingerprint'] in evidence.get('test_key_fingerprints', []),
           'actual TEST signer distinct from every official ALARM primary/subkey')
    for name in ('provider', 'database'):
        before = evidence.get(name+'_before')
        P.need(type(before) is dict and before == evidence.get(name+'_after')
               and type(before.get('paths')) is int and 0 < before['paths'] <= 100000
               and type(before.get('payload_bytes')) is int and 0 < before['payload_bytes'] <= 8589934592
               and re.fullmatch('[a-f0-9]{64}', before.get('sha256', '')), 'all349 original '+name+' paths and bytes unchanged')
    P.need(all(evidence.get(k) == manifest['copies'][manifest[k] if k in ('package', 'signature') else k] for k in ('package', 'signature', 'public_key')), 'installed exact package/signature/public-key custody')
    transaction = ['/usr/bin/pacman', '--config', '/project-test-input/pacman-project-test.conf', '--gpgdir', KEYRING,
                   '-U', '--noconfirm', '/project-test-input/'+manifest['package']]
    P.need(evidence.get('transaction') == transaction, 'normal offline Required TrustedOnly local pacman transaction')
    return {'schema': 1, 'status': 'PROJECT_TEST_DEPENDENCY_IMAGE_VERIFIED', 'test_only': True,
            'image_id': image_id, 'base_image': plan['base_image'], 'tuple_sha256': plan['tuple_sha256'],
            'inventory': P.pin(inventory_raw), 'evidence': P.pin(evidence_raw), 'package_count': 350,
            'installation': 'PROJECT TEST builder only', 'M2': 'NOT RUN', 'release': 'NOT ADMITTED'}
