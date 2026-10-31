#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check local source pins and optionally stage exactly the recipe's twelve files."""
import argparse,hashlib,json,os,re,shlex,shutil,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
FILES=('orphans3','remove.py','cachy-asahi-orphans','test_orphans.py','test_remove.py','test_retirement.py','live.py','live_policy.py','test_live.py','test_live_policy.py','test_live_supervision.py','protection-floor.json','README.md','READONLY.md','source-provenance.json','check_source.py','NOTICE','LICENSE')
PAYLOAD={
 'usr/bin/cachy-asahi-orphans':('orphans3',0o755),
 'usr/lib/cachy-asahi-orphans3/remove.py':('remove.py',0o644),
 'usr/lib/cachy-asahi-orphans3/live.py':('live.py',0o644),
 'usr/lib/cachy-asahi-orphans3/live_policy.py':('live_policy.py',0o644),
 'usr/lib/cachy-asahi-orphans3/readonly.py':('cachy-asahi-orphans',0o644),
 'usr/lib/cachy-asahi-orphans3/protection-floor.json':('protection-floor.json',0o644),
 'usr/share/cachy-asahi-orphans/protection-floor.json':('protection-floor.json',0o644),
 **{'usr/share/doc/cachy-asahi-orphans/'+n:(n,0o644) for n in ('README.md','READONLY.md','source-provenance.json')},
 **{'usr/share/licenses/cachy-asahi-orphans/'+n:(n,0o644) for n in ('NOTICE','LICENSE')}}
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--recipe',type=Path,default=HERE/'PKGBUILD');p.add_argument('--stage',type=Path);a=p.parse_args();recipe=a.recipe.read_text()
    sources=shlex.split(re.search(r'^source=\((.*?)\)',recipe,re.M|re.S).group(1));pins=shlex.split(re.search(r'^sha256sums=\((.*?)\)',recipe,re.M|re.S).group(1))
    assert sources==list(FILES) and len(pins)==len(FILES),'exact recipe source list required'
    for name,pin in zip(sources,pins):assert re.fullmatch('[0-9a-f]{64}',pin) and sha((HERE/name).read_bytes())==pin,'source pin differs: '+name
    provenance=json.loads((HERE/'source-provenance.json').read_bytes())
    for name,record in provenance['retained_sources'].items():assert sha((HERE/name).read_bytes())==record['sha256'],'retained source differs: '+name
    print(json.dumps(dict(status='PASS_SOURCE_PINS',source_files=len(FILES),payload_files=len(PAYLOAD)),sort_keys=True))
    if a.stage is not None:
        assert a.stage.is_absolute() and a.stage!=Path('/') and '..' not in a.stage.parts and not a.stage.exists(),'new absolute private stage required'
        assert a.stage.parent.stat().st_uid==os.geteuid() and not a.stage.parent.stat().st_mode&0o022,'private stage parent required'
        a.stage.mkdir(mode=0o700)
        for relative,(source,mode) in PAYLOAD.items():
            target=a.stage/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(HERE/source,target);target.chmod(mode)
        assert {str(path.relative_to(a.stage)) for path in a.stage.rglob('*') if path.is_file()}==set(PAYLOAD)
        for relative,(source,mode) in PAYLOAD.items():
            path=a.stage/relative;assert path.read_bytes()==(HERE/source).read_bytes() and path.stat().st_mode&0o777==mode
        cli=a.stage/'usr/bin/cachy-asahi-orphans'
        for args in (['--version'],['--help'],['remove','--help'],['live','--help'],['live','assess','--help']):
            result=subprocess.run([sys.executable,'-I','-B',str(cli),*args],text=True,capture_output=True,timeout=10);assert result.returncode==0,result.stderr
        print(json.dumps(dict(status='PASS_TWELVE_FILE_STAGING_AND_INSTALLED_HELP',stage=str(a.stage)),sort_keys=True))
if __name__=='__main__':main()
