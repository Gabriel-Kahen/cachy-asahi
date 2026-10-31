# SPDX-License-Identifier: MIT
"""Check the emitted workflow dependency graph without running its actors."""
import hashlib,json,os,re,shlex,unittest
from pathlib import Path

CHILD=Path(os.environ['EMITTED_SOURCE'])
WORKFLOWS=CHILD/'.github/workflows'

class WorkflowControls(unittest.TestCase):
 def dag(self,wf):
  steps=wf['jobs']['native']['steps'];ids={s['id']:i for i,s in enumerate(steps)if 'id'in s}
  self.assertEqual(len(ids),sum('id'in s for s in steps))
  def before(a,b):self.assertLess(a,b,'required producer/authority must precede consumer')
  def required(i):
   s=steps[i];self.assertFalse(s.get('continue-on-error',False));condition=s.get('if')
   if condition is None:return
   gate={'audio_inputs':'root_decisions','root_inputs':'audio_inputs','fdk_pair':'root_inputs','composition':'root_inputs'}.get(s.get('id'))
   if 'secrets.'in json.dumps(s):gate='root_inputs'
   self.assertIsNotNone(gate);terms=condition.removeprefix('${{').removesuffix('}}').strip().split(' && ')
   self.assertIn("steps."+gate+".outcome == 'success'",terms)
   for term in terms:self.assertRegex(term,r"^(?:always\(\)|!cancelled\(\)|inputs\.mode == 'build'|steps\.[A-Za-z_][A-Za-z_0-9-]*\.outcome == 'success')$")
  def checkout(path,ref):
   matches=[i for i,s in enumerate(steps)if s.get('with',{}).get('path')==path];self.assertEqual(len(matches),1);i=matches[0];s=steps[i]
   self.assertEqual(s['uses'],'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1');self.assertEqual(s['with']['ref'],ref);self.assertIs(s['with']['persist-credentials'],False);required(i);return i
  for i,s in enumerate(steps):
   for producer in re.findall(r'\bsteps\.([A-Za-z_][A-Za-z_0-9-]*)\.(?:outputs|outcome|conclusion)\b',json.dumps(s)):
    self.assertIn(producer,ids);before(ids[producer],i)
  wrapper=checkout('native4k-source','${{ inputs.source }}');held=checkout('expanded604-upgrade','b21a5864d5a4610b9181a1c270ac8821d8448a17')
  fresh=checkout('updater607-fresh16k-source','0db9341521b5cb5d9022715b5ba638b3e4018462');data=checkout('updater607-kernel-data-source','${{ inputs.kernel_input_source }}')
  exports=[i for i,s in enumerate(steps)if 'native4k-source/kernel_stage.py --source'in s.get('run','')];self.assertEqual(len(exports),1);export=exports[0];required(export)
  run=steps[export]['run'];command='python3 -I -B native4k-source/kernel_stage.py --source "$GITHUB_WORKSPACE/updater607-kernel-data-source" --revision "$KERNEL_DATA_SOURCE" --output "$RUNNER_TEMP/updater607-kernel-data"'
  self.assertEqual(run.count(command),1);before(wrapper,export);before(data,export)
  for name in('kernel_stage.py','custody.py','kernel_data.py'):
   digest=hashlib.sha256((CHILD/name).read_bytes()).hexdigest();binding="printf '%s  %s\\n' '"+digest+"' 'native4k-source/"+name+"' | sha256sum --check"
   self.assertEqual(run.count(binding),1);self.assertLess(run.index(binding),run.index(command))
  self.assertTrue(run.startswith('set -euo pipefail\n'));self.assertIn('test "$PAGE_PROFILE" = generic16k',run);self.assertIn('[[ "$KERNEL_DATA_SOURCE" =~ ^[0-9a-f]{40}$ ]]',run)
  self.assertEqual(steps[export]['env'],dict(PAGE_PROFILE='${{ inputs.page_profile }}',KERNEL_DATA_SOURCE='${{ inputs.kernel_input_source }}'))
  calls={}
  for i,s in enumerate(steps):
   text=s.get('run','').replace('\\\n',' ')
   for match in re.finditer(r'(?:"\$GITHUB_WORKSPACE/)?native4k-source/entry\.py"? (preflight|decisions|inputs|run) ',text):
    mode=match[1];self.assertNotIn(mode,calls);calls[mode]=i;required(i)
    args=shlex.split(text[match.end():].split('\n',1)[0])
    for flag,path,producer in(('--kernel-input','$RUNNER_TEMP/updater607-kernel-data',export),('--fresh16k-source','$GITHUB_WORKSPACE/updater607-fresh16k-source',fresh),('--implementation','$GITHUB_WORKSPACE/expanded604-upgrade',held)):
     self.assertEqual(args.count(flag),1);self.assertEqual(args[args.index(flag)+1],path);before(producer,i)
    before(wrapper,i)
  self.assertEqual(calls,dict(preflight=ids['root_policy'],decisions=ids['root_decisions'],inputs=ids['root_inputs'],run=ids['composition']))
  policy=steps[ids['root_policy']];self.assertEqual(policy['env']['IMPLEMENTATION_SOURCE'],'${{ inputs.source }}');self.assertEqual(policy['env']['WORKFLOW_SOURCE'],'${{ github.sha }}')
  self.assertLess(policy['run'].index(hashlib.sha256((CHILD/'entry.py').read_bytes()).hexdigest()),policy['run'].index('native4k-source/entry.py preflight'))
  for name in('root_policy','root_decisions','root_inputs','original_build','fdk_pair','composition'):required(ids[name])
  for a,b in(('root_policy','root_decisions'),('root_decisions','audio_inputs'),('audio_inputs','root_inputs'),('root_inputs','original_build'),('root_inputs','fdk_pair'),('root_inputs','composition')):before(ids[a],ids[b])
  secrets=[i for i,s in enumerate(steps)if 'secrets.'in json.dumps(s)];self.assertTrue(secrets)
  for i in secrets:
   before(ids['root_inputs'],i);required(i)
  tokens=[i for i,s in enumerate(steps)if 'GH_TOKEN'in s.get('env',{})];self.assertEqual(tokens,[ids['audio_inputs']]);before(ids['root_decisions'],tokens[0]);required(tokens[0])
 def test_emitted_workflow_operand_and_authority_dag(self):
  for name in('native-arm-build.yml','native-arm-latest607-updater-generic16k.yml'):
   with self.subTest(alias=name):self.dag(json.loads((WORKFLOWS/name).read_bytes()))
 def test_dag_rejects_missing_late_unbound_or_bypassed_prerequisites(self):
  wf=json.loads((WORKFLOWS/'native-arm-build.yml').read_bytes())
  changes=('old-order','missing-fresh','missing-data','unbound-helper','early-secret','early-native','skipped-export','bypassed-authority','forward-reference')
  for change in changes:
   bad=json.loads(json.dumps(wf));steps=bad['jobs']['native']['steps']
   if change=='old-order':steps.insert(3,steps.pop(6))
   elif change in('missing-fresh','missing-data'):del steps[3 if change=='missing-fresh'else 4]
   elif change=='unbound-helper':steps[5]['run']='\n'.join(line for line in steps[5]['run'].splitlines()if "'native4k-source/custody.py' |"not in line)+'\n'
   elif change=='early-secret':steps.insert(6,steps.pop(next(i for i,s in enumerate(steps)if 'secrets.'in json.dumps(s))))
   elif change=='early-native':steps.insert(6,steps.pop(next(i for i,s in enumerate(steps)if s.get('id')=='original_build')))
   elif change=='skipped-export':steps[5]['if']='false'
   elif change=='bypassed-authority':steps[6]['continue-on-error']=True
   else:steps[3]['with']['ref']='${{ steps.root_inputs.outputs.future }}'
   with self.subTest(change=change),self.assertRaises(AssertionError):self.dag(bad)

if __name__=='__main__':unittest.main()
