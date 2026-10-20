#!/usr/bin/env python3
"""Calibrate only genuine Root committed source metadata; actual run stays NULL."""
import argparse,json,re,shutil,subprocess
from pathlib import Path
from unittest.mock import patch
import replay as R

def bind(publication,authorization,output):
 raw=R.ordinary(publication.absolute(),65536);v=R.decode(raw);auth=R.ordinary(authorization.absolute(),1024**2)
 R.need(v.get('status')=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and v.get('files')==v.get('git_joins')==20 and type(v.get('source'))is str and re.fullmatch('[0-9a-f]{40}',v['source'])and type(v.get('ref'))is str and re.fullmatch('codex/[a-z0-9-]+',v['ref']),'genuine Root source20 publication metadata')
 a=R.decode(auth);a=a['files']if set(a)=={'files'}else a;R.need(a==R.read(R.HERE/'source-authorization.json')['files'],'whole exact20 Root source authorization')
 R.need(output.is_absolute()and not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in output.parents),'fresh ordinary Root source reader clone');R.need(R.SOURCE is R.REF is R.RUN is None,'source-only default metadata NULL')
 with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_GIT_API')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS_GIT_API')):R.preflight(R.HERE/'source')
 shutil.copytree(R.HERE,output);p=output/'replay.py';text=p.read_text()
 for a,b in(('SOURCE=None\n','SOURCE='+repr(v['source'])+'\n'),('REF=None\n','REF='+repr(v['ref'])+'\n')):R.need(text.count(a)==1,'one source metadata literal');text=text.replace(a,b)
 p.write_text(text);(output/'Root-source-publication.json').write_bytes(raw);(output/'Root-source-authorization.json').write_bytes(auth);result=dict(status='ROOT_COMMITTED_SOURCE_METADATA_ONLY_RUN_NULL',source=v['source'],ref=v['ref'],run=None,source_files=20,API='NOT_RUN',acceptance='NOT_GRANTED');(output/'Root-source-calibration.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('publication','authorization','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(bind(a.publication,a.authorization,a.output.absolute()),sort_keys=True))
