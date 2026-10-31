# SPDX-License-Identifier: MIT
import ast,hashlib,json,shutil
from pathlib import Path
import contract as P
import adapter as A
import build_pairs
PHASES=('install606','same-version606','remove604','reinstall606','final604')

def validate(r):
 P.need(type(r)is dict and r['status']=='PASS_SIGNED604_TO606_PRIVATE_LIFECYCLE'and(r['base_count'],r['installed_count'],r['restored_count'])==(604,606,604)and all(r[k]=='NOT_RUN'for k in('live_NM','kernel_mutation','hardware'))and r['release']=='NOT_ADMITTED','strict signed606 receipt')
 P.need([e['phase']for e in r['events']]==list(PHASES)and [e['count']for e in r['events']]==[606,606,604,606,604],'five actual606/604 transitions')
 for e in r['events']:
  P.need(all(e[k]is True for k in('all604_preserved','user_preserved','trust_preserved')),'complete604 user/trust/payload/rawDB preservation')
  if e['count']==604:P.need(e['payloads_absent']is True,'removed new payloads absent');continue
  P.need(e['signatures']is e['ownership']is e['dependencies']is True and len(e['observations'])==2 and {o['home']for o in e['observations']}=={'606-home-fresh','606-home-existing'},'both ordinary installed606 observations')
  for o in e['observations']:
   P.need(o['status']=='PASS_BOTH606_INSTALLED_PRIVATE_FIXTURES'and o['phase']==e['phase']and all(o[k]=='NOT_RUN'for k in('live_NM','kernel_mutation','hardware'))and set(o['products'])==set(P.ROLES),'exact installed program suite scope')
   for role,n in zip(P.ROLES,(27,28)):
    v=o['products'][role];P.need(v['controls']==n and v['version']=='0.1.0-2'and v['program_sha256']==P.policy(False)['products'][role]['source_files'][role[:-1]]['sha256']and v['suite']['exit']==0,'all exact installed27/28 controls/source/version')
    for stream in('stdout','stderr'):P.need(type(v['suite'][stream+'_bytes'])is int and 0<=v['suite'][stream+'_bytes']<=128*1024 and __import__('re').fullmatch('[0-9a-f]{64}',v['suite'][stream+'_sha256']),'bounded actual suite stream identities')
 P.need([r['phase']for r in r['ldconfig']]==['baseline604',*PHASES]and all(r['helper_exit']=='NOT_OBSERVED'for r in r['ldconfig']),'complete separate606 original auxiliary comparator checkpoints')
 return r

def emit_runner(root,runner):
 P.verify(root,bound=False);old=root/'held604'/P.OLD;shutil.copytree(old,runner);(runner/'lifecycle.py').write_text(A.lifecycle(root));(runner/'tools606.py').write_bytes((P.HERE/'tools606.py').read_bytes());(runner/'fixture606.py').write_bytes((P.HERE/'fixture606.py').read_bytes());shutil.copyfile(P.HERE/'expected606.lock',runner/'expected606.lock')
 accepted=runner/'accepted';accepted.mkdir();tools=root/'held-tools'
 for n,path in [('lifecycle.py','scripts/ci/welcome-native/lifecycle.py'),('root_upgrade.py','scripts/ci/full-root-upgrade/root_upgrade.py')]:shutil.copyfile(tools/path,accepted/n)
 raw=(tools/'scripts/ci/apps-cache-native/installed.py').read_text();raw=A.one(raw,'max_packages=574','max_packages=604');(runner/'installed604.py').write_text(raw)
 dns=tools/'packages/tools/cachy-asahi-dns2/test_dns.py';text=A.one(dns.read_text(),"str(HERE/'cachy-asahi-dns')","'/usr/bin/cachy-asahi-dns'");(runner/'test_dns2_installed.py').write_text(text)
 ledger=dict(A.proof(root),files={p.relative_to(runner).as_posix():P.pin(p.read_bytes())for p in sorted(runner.rglob('*'))if p.is_file()},installed604_derivation='ONLY_base_state_max_packages574_TO604_FULL_OTHER_BODY_HELD',dns_fixture_derivation='ONLY_EXPLICIT_INSTALLED_COMMAND_OPERAND')
 for p in(runner,*runner.rglob('*')):
  if not p.is_symlink():p.chmod(0o755 if p.is_dir()else 0o644)
 return runner,ledger

def prepare(root,producer,out,owned,ready,C):
 original=C.read(ready/'manifest.json');context=build_pairs.prepare(root,producer,out,owned,original,C);runner,ledger=emit_runner(root,out/'runner606');(context/'runner-derivation.json').write_bytes(P.encoded(ledger));return context,runner

def prepare_export(out,report):
 life=out/'container/tools606.json'
 if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION':validate(json.loads(life.read_bytes()))
 report['tools606_scope']=dict(base_source=P.BASE,base604_preserved=True if report.get('status')=='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'else'UNKNOWN',builds=4,pairs=2,host_NM='NOT_RUN',host_sysctl='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def export_names(out):
 names=[]
 for root in('tools-builds','tools606'):
  home=out/root
  if home.exists():names.extend(str(p.relative_to(out))for p in sorted(home.rglob('*'))if p.is_file())
 home=out/'container'
 if home.exists():names.extend(str(p.relative_to(out))for p in sorted(home.iterdir())if p.is_file()and p.name.startswith('tools606'))
 return names
