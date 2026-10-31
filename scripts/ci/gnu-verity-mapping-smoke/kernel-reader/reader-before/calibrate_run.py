"""Clone for one genuine Root-resolved actual; preserve default NULL files."""
from pathlib import Path
import argparse,hashlib,json,re,shutil,subprocess,sys
from unittest.mock import patch
import replay as R
def main(metadata,run,output):
 R.need(type(run)is str and re.fullmatch('[1-9][0-9]{0,19}',run),'genuine positive decimal actual ID')
 raw=R.ordinary(metadata.absolute(),1024**2);m=R.decode(raw)
 R.need(type(m.get('id'))is int and str(m['id'])==run and type(m.get('run_attempt'))is int and m['run_attempt']==1 and m.get('head_sha')==R.SOURCE and m.get('head_branch')==R.REF and m.get('workflow_id')==381664314 and m.get('path')=='.github/workflows/native-arm-build.yml'and m.get('name')=='native-arm-gnu-verity-kernel-build-only'and m.get('event')=='workflow_dispatch'and m.get('repository',{}).get('full_name')=='Gabriel-Kahen/cachy-asahi'and m.get('status')in('queued','pending','in_progress','completed','waiting'),'Root genuine resolved source/workflow/run metadata')
 R.need(not output.exists()and output.is_absolute()and output.parent.is_dir()and not any(p.is_symlink()for p in output.parents),'fresh ordinary Root reader clone')
 with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_GIT_API')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS_GIT_API')):R.preflight(R.HERE/'source')
 output.mkdir(mode=0o700);shutil.copytree(R.HERE/'source',output/'source')
 for name in('source-authorization.json','collect.py','replay.py','binding.template.json','selection.template.json','failure_facts.py'):shutil.copyfile(R.HERE/name,output/name)
 p=output/'replay.py';text=p.read_text();R.need(text.count('RUN = None\n')==1,'defaultRUN must remain NULL');p.write_text(text.replace('RUN = None\n','RUN = '+repr(run)+'\n'))
 selected=dict(source_sha=R.SOURCE,ref=R.REF,run_id=run,run_attempt='1')
 for n,v in(('Root-selection.json',selected),('Root-binding.json',dict(selected,artifact_sha256=None))):(output/n).write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
 (output/'Root-calibration.json').write_text(json.dumps(dict(status='PASS_GENUINE_METADATA_SOURCE_ONLY_NOT_NATIVE_ACCEPTANCE',metadata=R.pin(raw),source=R.SOURCE,ref=R.REF,run=run,source_files=19,changed_module='EXACT_RUN_LITERAL_ONLY',collector='BYTE_HELD',default_templates='ALL_NULL_HELD',API='NOT_RUN'),sort_keys=True,indent=2)+'\n')
 print('PASS exact Root actual selection clone; no GET/collection/native acceptance')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--metadata',type=Path,required=True);p.add_argument('--run',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();main(a.metadata,a.run,a.output)
