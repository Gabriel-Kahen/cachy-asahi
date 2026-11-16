# SPDX-License-Identifier: MIT
"""Actual Bash helpers in fictional private files; no guest, ALPM, GPG or VM."""
import base64
import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
NONCE='a'*32
TAGS=('version','functional','corelist','json','perldoc','podtext','podcheck','prove','sha','splain','paths','sync')
spec=importlib.util.spec_from_file_location('probe_diagnostic_protocol',HERE/'protocol.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
STAT=r'''
stat() {
 local path=${@: -1} value rest
 value=$(/usr/bin/stat "$@") || return
 case "$2" in
  '%u:%g:%a'|'%u:%g:%h:%a:%s:%d:%i:%y:%z')
   if [[ $path == "$U" || $path == "$U/"* ]];then
    rest=${value#*:};rest=${rest#*:}
    local uid=${MODEL_UID:-1000};[[ $path != "$U" ]] || uid=1000
    printf '%s:%s:%s\n' "$uid" "$uid" "$rest"
   else printf '%s\n' "$value";fi;;
  *) printf '%s\n' "$value";;
 esac
}
head() {
 if [[ ${MODEL_CHANGE:-0} == 1 && ${@: -1} == "$U/version.log" && ! -f $D/changed ]];then
  /usr/bin/head "$@"
  printf MUTATED > "$U/version.log";touch "$D/changed"
 else /usr/bin/head "$@";fi
}
'''

def run(body,*,data=b'fiction stderr\n',alias=None,mode=0o600,owner=1000,change=False,cap=16384):
 with tempfile.TemporaryDirectory(prefix='perl-probe-diagnostic-DATA-')as name:
  root=Path(name);stage=root/'packet';runtime=root/'run';user=runtime/'user'
  stage.mkdir(mode=0o755);runtime.mkdir(mode=0o755);user.mkdir(mode=0o700)
  path=user/'version.log'
  if data is not None:path.write_bytes(data);path.chmod(mode)
  if alias=='symlink':path.rename(root/'outside');path.symlink_to(root/'outside')
  elif alias=='hardlink':os.link(path,root/'outside')
  elif alias=='fifo':path.unlink();os.mkfifo(path,0o600)
  elif alias=='directory':path.unlink();path.mkdir(mode=0o700)
  elif alias=='parent':user.rename(root/'other-user');user.symlink_to(root/'other-user')
  (stage/'other-secret-looking-DATA').write_bytes(b'NEVER_EXPORT_OTHER_FILE')
  (user/'functional.log').write_bytes(b'NOT_THE_CURRENT_LOG')
  source=(HERE/'guest/probe.sh').read_text();prefix=source.split('[[ ( $# == 1',1)[0]
  setup='\n. '+shlex.quote(str(HERE/'guest/case.sh'))+'\n'+STAT+'\nD='+shlex.quote(str(stage))+';O='+shlex.quote(str(runtime))+';U=$O/user\nnonce='+NONCE+';log_bytes='+str(cap)+'\n'
  script=root/'control.sh';script.write_text(prefix+setup+body+'\n')
  result=subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(script)],cwd=root,
    env=dict(PATH='/usr/bin:/bin',HOME=str(root),LC_ALL='C',MODEL_UID=str(owner),MODEL_CHANGE=str(int(change))),capture_output=True,timeout=8)
  result.evaluated=(root/'EVALUATED').exists()
  return result


def hold_body(tag='version'):
 return 'failure_phase=probe_version;probe_log_tag='+shlex.quote(tag)+'\ntrap finish EXIT\nexit 134\n'

def diagnostic(raw):
 lines=[line for line in raw.splitlines()if line.startswith(b'PERL5423_PROBE_LOG ')]
 if not lines:return None
 if len(lines)!=1:raise AssertionError('one diagnostic only')
 match=re.fullmatch(rb'PERL5423_PROBE_LOG ([0-9a-f]{32}) (probe_[a-z]+) ([a-z]+) BYTES=([0-9]+) PREFIX_BYTES=([0-9]+) BASE64=([A-Za-z0-9+/]*={0,2})',lines[0])
 if match is None:raise AssertionError(lines[0])
 return match,base64.b64decode(match[6],validate=True)


class Controls(unittest.TestCase):
 def assert_hold(self,result,phase='probe_version'):
  self.assertEqual(result.returncode,134,result.stderr.decode())
  self.assertEqual(P.frame(result.stdout,NONCE),dict(STATUS='HOLD',FAILURE_SOURCE='PROBE',FAILED_PHASE=phase,ROOT_SUMMARY_STATE='ABSENT',EXIT_STATUS='134'))
  self.assertNotIn(b'FUNCTIONAL=PASS',result.stdout);self.assertNotIn(b'COMMANDS=PASS',result.stdout)
 def test_actual_bounded_exit134_stderr_and_fixed_progress_survive(self):
  result=run('trap finish EXIT\ncd "$U"\nrun_probe version 2 /usr/bin/bash -c '+shlex.quote('printf "modeled abort stderr\\n" >&2;exit 134'),data=None)
  self.assert_hold(result);match,raw=diagnostic(result.stdout);self.assertEqual(raw,b'modeled abort stderr\n')
  self.assertIn(('PERL5423_PROBE_PROGRESS '+NONCE+' probe_version version\n').encode(),result.stdout)
  self.assertLess(result.stdout.index(b'PERL5423_PROBE_LOG '),result.stdout.index(b'PERL5423_PROBE_BEGIN '))
 def test_binary_terminal_control_and_frame_text_stay_encoded_and_bounded(self):
  data=b'\x00\x1b]3008;evil\x1b\\\r\nPERL5423_PROBE_BEGIN '+NONCE.encode()+b'\nSTATUS=PASS\n%snasty\xff'+b'X'*9000
  result=run(hold_body(),data=data);self.assert_hold(result);match,raw=diagnostic(result.stdout)
  self.assertEqual(raw,data[:4096]);self.assertEqual(int(match[4]),len(data));self.assertEqual(int(match[5]),4096)
  self.assertTrue(all(c==10 or 32<=c<=126 for c in result.stdout));self.assertEqual(result.stdout.count(b'PERL5423_PROBE_BEGIN '),1)
  self.assertNotIn(b'NOT_THE_CURRENT_LOG',result.stdout);self.assertNotIn(b'NEVER_EXPORT_OTHER_FILE',result.stdout)
 def test_missing_unsafe_oversized_and_changing_logs_are_ignored(self):
  cases=[dict(data=None),dict(alias='symlink'),dict(alias='hardlink'),dict(alias='fifo'),dict(alias='directory'),dict(alias='parent'),dict(mode=0o644),dict(owner=1001),dict(data=b'X'*17000),dict(change=True)]
  for values in cases:
   with self.subTest(values=values):
    result=run(hold_body(),**values);self.assert_hold(result);self.assertIsNone(diagnostic(result.stdout))
 def test_empty_log_is_honestly_encoded(self):
  result=run(hold_body(),data=b'');self.assert_hold(result);match,raw=diagnostic(result.stdout);self.assertEqual(raw,b'');self.assertEqual((match[4],match[5]),(b'0',b'0'))
 def test_fixed_tag_allowlist_and_no_path_or_format_evaluation(self):
  body='for tag in '+ ' '.join(TAGS)+';do probe_tag "$tag";done\nif run_probe '+shlex.quote('$(touch EVALUATED)/../%s')+' 1 /usr/bin/false;then exit 9;fi\n'+hold_body('../other-secret-looking-DATA')
  result=run(body);self.assert_hold(result);self.assertIsNone(diagnostic(result.stdout));self.assertNotIn(b'PROBE_PROGRESS',result.stdout);self.assertFalse(result.evaluated)
  self.assertEqual(set(re.findall(r'^run_probe ([a-z]+) ',(HERE/'guest/probe.sh').read_text(),re.M)),set(TAGS))
 def test_root_HOLD_has_priority_over_probe_excerpt(self):
  frame=(f'PERL5423_RESTORED_BEGIN {NONCE}\nSTATUS=HOLD\nFAILED_PHASE=install\nEXIT_STATUS=1\nPERL5423_RESTORED_END {NONCE}\n').encode()
  body='failure_phase=probe_version;probe_log_tag=version;summary_state=HOLD\nsummary_lines=('+ ' '.join(shlex.quote(line)for line in frame.decode().splitlines())+')\ntrap finish EXIT\nrelay_root_summary\nexit 1\n'
  result=run(body);self.assertEqual((result.returncode,result.stdout),(1,b'\n'+frame));self.assertNotIn(b'PROBE_LOG',result.stdout)
 def test_installed_frame_gets_its_own_line_after_OSC_prefix(self):
  source=(HERE/'guest/probe.sh').read_text();line=next(line for line in source.splitlines()if line.startswith("printf '\\nPERL5423_INSTALLED_BEGIN "))
  result=run("printf '\\033]3008;type=command\\033\\\\'\n"+line)
  self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(P.frame(result.stdout,NONCE,'INSTALLED'),P.INSTALLED)
  class Serial:
   data=result.stdout
   def until(self,pattern):
    match=re.search(pattern,self.data)
    if match is None:raise ValueError('strict frame boundary absent')
    return match
  self.assertEqual(P.wait_phase(Serial(),NONCE,'INSTALLED'),P.INSTALLED)
  old=result.stdout.replace(b'\x1b\\\nPERL5423_INSTALLED_BEGIN',b'\x1b\\PERL5423_INSTALLED_BEGIN')
  with self.assertRaises(ValueError):P.frame(old,NONCE,'INSTALLED')
 def test_tools_caps_and_original_bounded_function_are_unchanged(self):
  spec=importlib.util.spec_from_file_location('probe_tools_contract',HERE/'contracts.py');k=importlib.util.module_from_spec(spec);spec.loader.exec_module(k)
  self.assertTrue({'base64','head','stat','sha256sum'}<=set(k.TOOLS));self.assertEqual(len(k.TOOLS),37)
  body=(HERE/'guest/probe.sh').read_text();self.assertIn('selected <= 4096',body);self.assertNotIn('log_bytes=',body)
  self.assertIn('bounded "$seconds" "$tag.log" "$@"',body);self.assertIn('exit "$rc"',body)

if __name__=='__main__':unittest.main(verbosity=2)
