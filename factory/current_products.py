# SPDX-License-Identifier: MIT
"""Actual installed Apps8 metadata publication and KSM2 read-only command in guest."""
import hashlib,json,os,subprocess
from pathlib import Path

def need(ok,why):
    if not ok:raise ValueError(why)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def _original_validate(value,page):
    need(value['status']=='ACTUAL_INSTALLED_APPS8_AND_KSM2_READONLY'and value['uid']==23001 and value['page_size']==page,'actual ordinary-user current-product context')
    apps=value['apps'];need(apps['status']=='OBSERVED_LOCAL_DB_METADATA'and apps['package_count']==606 and apps['applied']=='NOT_APPLIED'and value['apps_expected_lock']==value['expected606_lock']and apps['sha256']==value['apps_file_sha256'],'actual Apps8 published complete606 metadata identity')
    k=value['ksm'];need(k['before_run']==k['after_run'],'KSM run settings unchanged')
    if k['returncode']==3:need(k['stdout']==''and k['stderr']in('cachy-asahi-ksmctl: KSM interface unavailable\n','cachy-asahi-ksmctl: KSM run interface unavailable\n')and k['report']is None,'exact KSM2 unsupported interface observation only')
    else:
        r=k['report'];need(k['returncode']==0 and k['stderr']==''and r['tool']=='cachy-asahi-ksmctl'and r['version']=='0.1.0'and r['mode']=='read-only'and r['management_available']is False and r['page_size_bytes']==page,'actual KSM2 runtime page-size report')
    return value

def run(share,home,env):
    need(os.getuid()==os.geteuid()==23001,'real managed ordinary user only')
    target=home/'apps8-current606-inventory.json';need(not target.exists(),'fresh actual Apps8 metadata publication')
    apps8_runtime=_apps8_runtime()
    installed_before=apps8_runtime.observe()
    argv=['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(target)];p=subprocess.run(argv,env=env,capture_output=True,timeout=35)
    need(p.returncode==0 and not p.stderr and len(p.stdout)<=65536,'actual bounded installed Apps8 command')
    installed_after=apps8_runtime.observe();apps8_runtime.validate(installed_before,installed_after)
    apps=json.loads(p.stdout);raw=target.read_bytes();need(len(raw)<=64*1024**2 and target.lstat().st_nlink==1 and target.lstat().st_mode&0o777==0o600,'actual private Apps8 inventory')
    inventory=json.loads(raw);expected=(share/'expected.lock').read_bytes();wanted=dict(line.split()for line in expected.decode().splitlines());actual={r['name']:r['version']for r in inventory['packages']};need(actual==wanted and len(actual)==len(inventory['packages'])==606,'actual Apps8 matches every current606 package/version')
    def setting():
        try:value=Path('/sys/kernel/mm/ksm/run').read_bytes()
        except FileNotFoundError:return None
        need(value in(b'0\n',b'1\n',b'2\n'),'bounded actual KSM run interface');return value.decode()
    before=setting();q=subprocess.run(['/usr/bin/cachy-asahi-ksmctl','--json','--report'],env=env,capture_output=True,timeout=5);after=setting();need(len(q.stdout)+len(q.stderr)<=65536,'bounded actual KSM2 command')
    stdout,stderr=q.stdout.decode(),q.stderr.decode();report=json.loads(stdout)if q.returncode==0 else None
    value=dict(status='ACTUAL_INSTALLED_APPS8_AND_KSM2_READONLY',apps8_identity=dict(before=installed_before,after=installed_after),uid=os.getuid(),page_size=os.sysconf('SC_PAGE_SIZE'),apps=apps,apps_file_sha256=digest(raw),apps_expected_lock=digest(''.join(n+' '+v+'\n'for n,v in sorted(actual.items())).encode()),expected606_lock=digest(expected),ksm=dict(returncode=q.returncode,stdout=stdout,stderr=stderr,report=report,before_run=before,after_run=after),scope='METADATA_AND_READONLY_COUNTER_OBSERVATIONS_NO_APPLY_OR_SHARING_OR_PERFORMANCE')
    validate(value,os.sysconf('SC_PAGE_SIZE'));return value

def _apps8_runtime():
    import importlib.util
    path=Path(__file__).resolve().parent/'apps8_runtime.py'
    spec=importlib.util.spec_from_file_location('_installed_apps8_identity',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def validate(value,page):
    _original_validate(value,page)
    apps8_runtime=_apps8_runtime()
    apps8_runtime.validate(value['apps8_identity']['before'],value['apps8_identity']['after'])
    return value
