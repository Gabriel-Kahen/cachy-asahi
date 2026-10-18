# SPDX-License-Identifier: MIT
"""Finite whole-pin derivatives: two products, signed fixture-only lifecycle, six actors."""
import ast,hashlib,json,os,stat,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
OLD='scripts/ci/tools-native/'

def read(source,name):
 row=json.loads((HERE/'original-pins.json').read_bytes())[name];path=source/name
 if any(p.is_symlink()for p in(path,*path.parents)):raise ValueError('original source alias')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or info.st_size!=row['bytes']:raise ValueError('original source type/size')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(row['bytes']+1)
  after=os.fstat(fd)
  if(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('original drift')
 finally:os.close(fd)
 if len(raw)!=row['bytes']or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('original source hash: '+name)
 return raw.decode()

def replace(raw,before,after):
 if raw.count(before)!=1:raise ValueError('one exact source seam: '+before[:100])
 return raw.replace(before,after)

def function(raw,name,body):
 node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name)
 lines=raw.splitlines(keepends=True);lines[node.lineno-1:node.end_lineno]=[body];return ''.join(lines)

def text(source,name):
 raw=read(source,OLD+name)
 if name=='contract.py':
  raw=replace(raw,"NAMES=('cachy-asahi-mirrors','cachy-asahi-zsh-syntax-highlighting','cachy-asahi-zsh-history-substring-search')","NAMES=('cachy-asahi-dns','cachy-asahi-sysctl')")
  raw=replace(raw,"LABEL='org.cachy-asahi.tools-native.job'","LABEL='org.cachy-asahi.dns-sysctl-native.job'")
  raw=replace(raw,'import shlex\n','import shlex\nimport selection as S\n')
  raw=function(raw,'verify_source',"def verify_source(source):\n    return S.verify_source(source)\n")
  raw=function(raw,'recipe',"def recipe(source,name):\n    return S.recipe(source,name)\n")
  raw=function(raw,'spec',"def spec():\n    return S.policy()\n")
  raw=function(raw,'final_spec',"def final_spec():\n    return S.policy()\n")
  raw=function(raw,'validate_lifecycle',"def validate_lifecycle(value):\n    from rules import validate\n    return validate(value)\n")
  raw=replace(raw,"return dict(status='PASS_CHECK_EXIT',method='makepkg check() exit0; additional installed behavior required')","need(not re.search(r'\\bskipped=[1-9]|\\bOK \\(skipped=',text),'native test skips forbidden')\n    return dict(status='PASS_CHECK_EXIT_NO_SKIPS',method='makepkg check() exit0 plus exact markers; installed behavior separate')")
 elif name=='run.py':
  raw=replace(raw,'import contract as C\n','import contract as C\nimport adapter as A\n')
  raw=replace(raw,"    C.need(platform.system()=='Linux'","    C.final_spec() # NULL selection fails before actors, output, native observers or signing.\n    C.need(platform.system()=='Linux'")
  raw=replace(raw,"scope='THREE_UNSELECTED_TOOLS_CANDIDATES'","scope='DNS_SYSCTL_NATIVE_PAIRS_AND_PRIVATE_FIXTURES_ONLY'")
  raw=replace(raw,"len(self)<8","len(self)<7")
  raw=replace(raw,"base=={r['name']:r['version'] for r in selected['packages']}","base=={r['name']:r['version'] for r in selected['packages']} and C.digest(lock)==C.final_spec()['base_inventory_sha256'] and not set(C.NAMES)&base.keys()")
  raw=replace(raw,"        container='cachy-asahi-product-lifecycle-'", "        runner=A.runner(source,context)\n        signer_api=C.load('dns_sysctl_original_TEST_signer',source/'scripts/ci/full-development-composition/run.py')\n        archives=[context/products[n]['archive'] for n in C.NAMES]\n        signer=signer_api.sign(context,out,archives)\n        report['signer']=dict(fingerprint=signer,authority='EPHEMERAL_TEST_ONLY')\n        subprocess.run(['gpgconf','--homedir',str(out/'test-signing'),'--kill','all'],check=True,capture_output=True,timeout=20)\n        save(context/'control.json',dict(signer=signer))\n        A.public_tree(context)\n        container='cachy-asahi-product-lifecycle-'")
  before="command(docker(image,container,out,root=True)+['--env=CACHY_ASAHI_TOOLS_LIFECYCLE=1',\n            '--mount',f'type=bind,src={context},dst=/inputs,readonly',\n            '--mount',f'type=bind,src={source}/scripts/ci/welcome-native,dst=/accepted,readonly',\n            '--mount',f'type=bind,src={source}/scripts/ci/zsh-highlighting-native,dst=/highlighting-fixture,readonly',\n            '--mount',f'type=bind,src={HERE},dst=/runner,readonly',"
  after="command(docker(image,container,out,root=True)+['--env=CACHY_ASAHI_APPS_CACHE_OPERATION=lifecycle',\n            '--mount',f'type=bind,src={context},dst=/inputs,readonly',\n            '--mount',f'type=bind,src={runner},dst=/runner,readonly',"
  raw=replace(raw,before,after)
  raw=replace(raw,"        context=out/'lifecycle-inputs';context.mkdir();", "        profile=C.load('dns_private_profile_actor',HERE/'profile_actor.py')\n        report['private_profile']=profile.launch(C,source,out,image,products,docker,command,containers)\n        save(out/'private-profile.json',report['private_profile'])\n        context=out/'lifecycle-inputs';context.mkdir();")
  raw=replace(raw,"status='PASS_NATIVE_TOOLS_PAIRS_AND_CLI_PTY_LIFECYCLE'","status='PASS_NATIVE_DNS_SYSCTL_PAIRS_AND_PRIVATE_PROFILE_LIFECYCLE'")
 elif name=='job.py':
  raw=raw.replace('scripts/ci/tools-native','scripts/ci/dns-sysctl-native')
  raw=replace(raw,"len(names)<=8","len(names)<=7")
  raw=replace(raw,"len(owner['containers'])==8","len(owner['containers'])==7")
  raw=replace(raw,"len(ordered['consumer']['containers'])==8","len(ordered['consumer']['containers'])==7")
  raw=replace(raw,"report['status']=='PASS_NATIVE_TOOLS_PAIRS_AND_CLI_PTY_LIFECYCLE'","report['status']=='PASS_NATIVE_DNS_SYSCTL_PAIRS_AND_PRIVATE_PROFILE_LIFECYCLE'")
  marker="    try:\n        C.verify_source(source)\n"
  extra="    copy(runtime/'lifecycle-inputs/control.json','TEST-signing/control.json',65536)\n    copy(runtime/'lifecycle-inputs/TEST-public.asc','TEST-signing/TEST-public.asc',65536)\n    copy(runtime/'lifecycle-inputs/runner-derivations.json','runner-derivations.json',65536)\n    for product in C.NAMES:\n        archive=product+'-'+C.version(source,product)+'-any.pkg.tar.'\n        for suffix in ('xz','zst'):\n            copy(runtime/'lifecycle-inputs'/(archive+suffix+'.sig'),'TEST-signing/'+archive+suffix+'.sig',65536,False)\n"
  raw=replace(raw,marker,extra+marker)
  raw=replace(raw,"C.need(not result['errors'],'complete closed candidate evidence required')","C.need(read(runtime/'lifecycle-inputs/control.json')['signer']==report['signer']['fingerprint']==report['lifecycle']['signer'] and report['signer']['authority']=='EPHEMERAL_TEST_ONLY','exact ephemeral TEST signer join required')\n        for product,row in report['products'].items():\n            C.need('TEST-signing/'+row['builds'][0]['archive']+'.sig' in result['files'],'TEST archive signature missing')\n        C.need(not result['errors'],'complete closed candidate evidence required')")
  raw=replace(raw,"        C.need(not result['errors'],'complete closed candidate evidence required')", "        from rules import validate_profile\n        profile=read(runtime/'private-profile.json');C.need(profile==report['private_profile'],'parent/standalone private NM receipt differs')\n        validate_profile(profile,C.digest(source/'packages/tools/cachy-asahi-dns/cachy-asahi-dns'))\n        C.need(profile['native_archive_sha256']==report['products']['cachy-asahi-dns']['builds'][0]['sha256'],'private profile/build-A archive identity differs')\n        C.need(not result['errors'],'complete closed candidate evidence required')")
  copy_marker="    copy(proof,'source-proof.json',65536);copy(cleanup_path,'ordered-cleanup.json',65536)\n"
  raw=replace(raw,copy_marker,copy_marker+"    copy(runtime/'private-profile.json','runtime/private-profile.json',1024**2)\n    copy(runtime/'private-profile.log','runtime/private-profile.log',16*1024**2)\n    for name in ('receipt.json','NetworkManager.log','dbus.log'):\n        copy(runtime/'private-profile-actor'/name,'runtime/private-profile/'+name,1024**2)\n")
  raw=raw.replace('PASS_NATIVE_TOOLS_CANDIDATES_CLI_PTY_LIFECYCLE','PASS_NATIVE_DNS_SYSCTL_CANDIDATES_PRIVATE_PROFILE_LIFECYCLE')
 return raw

def module(source,name):
 m=types.ModuleType('dns_sysctl_'+name.replace('.','_'));m.__file__=str(HERE/name);sys.modules[m.__name__]=m
 exec(compile(text(source,name),m.__file__,'exec'),m.__dict__);return m

def public_tree(path):
 for item in(path,*path.rglob('*')):
  if not item.is_symlink():item.chmod(0o755 if item.is_dir()else 0o644)

def runner(source,context):
 import shutil
 runner=context/'runner';runner.mkdir();accepted=runner/'accepted';accepted.mkdir()
 (runner/'contract.py').write_text(text(source,'contract.py'))
 for name in('selection.py','rules.py','lifecycle.py','fixture_checks.py','input-policy.json'):shutil.copyfile(HERE/name,runner/name)
 for name,path in [('installed.py','scripts/ci/apps-cache-native/installed.py'),('accepted/lifecycle.py','scripts/ci/welcome-native/lifecycle.py'),('accepted/root_upgrade.py','scripts/ci/full-root-upgrade/root_upgrade.py')]:
  read(source,path);shutil.copyfile(source/path,runner/name)
 dns=source/'packages/tools/cachy-asahi-dns/test_dns.py';raw=dns.read_text()
 expected=json.loads((HERE/'input-policy.json').read_bytes())['products']['cachy-asahi-dns']['source_files']['test_dns.py']
 if len(dns.read_bytes())!=expected['bytes']or hashlib.sha256(dns.read_bytes()).hexdigest()!=expected['sha256']:raise ValueError('DNS fixture source differs')
 raw=replace(raw,"str(HERE/'cachy-asahi-dns')","'/usr/bin/cachy-asahi-dns'");(runner/'test_dns_installed.py').write_text(raw)
 rows={p.relative_to(runner).as_posix():dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in sorted(runner.rglob('*'))if p.is_file()}
 (context/'runner-derivations.json').write_text(json.dumps(dict(status='SOURCE_CLOSED_COUNTED_DERIVATIVES',files=rows),sort_keys=True,indent=2)+'\n')
 return runner
