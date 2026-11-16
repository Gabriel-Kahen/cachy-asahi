# SPDX-License-Identifier: MIT
"""Actual checkpoint helpers on private files, with fictional Root stat ownership.

No guest entry, VM, package manager, GPG, network, lease or resource query runs.
The publisher requires fixed /usr/bin/mv admission by the integrating coordinator.
No durability or actual guest phase is established by these local controls.
"""
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
NONCE='a'*32
RECORD='root-phase.checkpoint'
TEMP='.root-phase.checkpoint.tmp'
PHASES={'guard','rtc_clock','users','baseline','trust','dependency_install','official_trust','install','installed_payload',
        'installed_metadata','probe_wait','retain_outputs','recovery','cache_restoration','restoration'}
STAT=r'''
stat() {
 local value rest count=0
 value=$(/usr/bin/stat "$@") || return
 case "$2" in
  '%u:%g:%a'|'%u:%g:%h'|'%u:%g:%h:%a'|'%u:%g:%h:%a:%s:%d:%i:%y:%z')
   rest=${value#*:};rest=${rest#*:}
   if [[ $2 == '%u:%g:%h:%a:%s:%d:%i:%y:%z' && ${MODEL_DRIFT:-0} == 1 ]];then
    [[ ! -f $MODEL_COUNT ]] || read -r count < "$MODEL_COUNT"
    printf '%s\n' "$((count+1))" > "$MODEL_COUNT"
    (( count == 0 )) || rest=${rest}CHANGED
   fi
   printf '%s:0:%s\n' "${MODEL_UID:-0}" "$rest";;
  *) printf '%s\n' "$value";;
 esac
}
'''


def record(phase='installed_metadata',nonce=NONCE):return f'PERL5423_ROOT_PHASE_V1 {nonce} {phase}\n'.encode()


def run(body,*,probe=False,data=None,mode=0o644,alias=None,owner=0,drift=False,summary=None):
    with tempfile.TemporaryDirectory(prefix='perl-root-progress-DATA-')as name:
        root=Path(name);stage=root/'stage';stage.mkdir(mode=0o755);runtime=root/'run'
        path=stage/RECORD
        if data is not None:path.write_bytes(data);path.chmod(mode)
        if alias=='symlink':path.rename(root/'outside');path.symlink_to(root/'outside')
        if alias=='hardlink':os.link(path,root/'outside')
        if alias=='fifo':os.mkfifo(path,0o644)
        if summary is not None:
            runtime.mkdir(mode=0o755);(runtime/'summary.env').write_bytes(summary);(runtime/'summary.env').chmod(0o644)
        source=(HERE/'guest'/('probe.sh'if probe else'root.sh')).read_text()
        marker='[[ ( $# == 1'if probe else'finish() {'
        prefix=source.split(marker,1)[0]
        script=root/'helpers.sh';script.write_text(prefix+STAT+'\nD=$1;O=$2;nonce=$3;probe_wait_seconds=0\n'+body+'\n')
        result=subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(script),str(stage),str(runtime),NONCE],
            env=dict(PATH='/usr/bin:/bin',HOME=str(root),LC_ALL='C',MODEL_UID=str(owner),MODEL_DRIFT=str(int(drift)),MODEL_COUNT=str(root/'count')),
            cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        files={p.name:p.read_bytes()for p in stage.iterdir()if p.is_file()and not p.is_symlink()}
        modes={p.name:stat.S_IMODE(p.lstat().st_mode)for p in stage.iterdir()}
        return dict(exit=result.returncode,stdout=result.stdout,stderr=result.stderr,files=files,modes=modes,
                    outside=(root/'outside').read_bytes()if(root/'outside').is_file()else None,evaluated=(root/'EVALUATED').exists())


class Controls(unittest.TestCase):
    def test_real_atomic_replacement_keeps_open_old_record_and_one_new_file(self):
        result=run('''checkpoint_phase guard
exec 7< "$D/root-phase.checkpoint"
before=$(/usr/bin/stat -c '%i' "$D/root-phase.checkpoint")
checkpoint_phase installed_metadata
after=$(/usr/bin/stat -c '%i' "$D/root-phase.checkpoint")
[[ $before != "$after" ]]
head -c 128 <&7
[[ $(/usr/bin/stat -c '%h:%a' "$D/root-phase.checkpoint") == 1:644 ]]
[[ ! -e $D/.root-phase.checkpoint.tmp ]]
''')
        self.assertEqual(result['exit'],0);self.assertEqual(result['stdout'],record('guard'))
        self.assertEqual(result['files'],{RECORD:record()});self.assertEqual(result['modes'][RECORD],0o644)

    def test_finite_phase_size_and_twenty_write_bound(self):
        result=run('''for (( i=0;i<20;i++ ));do checkpoint_phase install;done
checkpoint_phase probe_wait
[[ $root_phase_writes == 21 && $phase == probe_wait ]]
''')
        self.assertEqual(result['exit'],0);self.assertEqual(result['files'][RECORD],record('install'))
        self.assertLessEqual(len(result['files'][RECORD]),128)
        result=run("if write_root_phase '$(touch EVALUATED)';then exit 9;fi")
        self.assertEqual(result['exit'],0);self.assertFalse(result['files']);self.assertFalse(result['evaluated'])

    def test_publisher_refuses_existing_unsafe_or_foreign_record_without_clobber(self):
        for values in(dict(data=record(nonce='b'*32)),dict(data=b'PARTIAL'),dict(data=record(),mode=0o666),
                      dict(data=record(),alias='symlink'),dict(data=record(),alias='hardlink'),dict(data=record(),owner=1000)):
            with self.subTest(values=values):
                result=run('if write_root_phase probe_wait;then exit 9;fi',**values)
                self.assertEqual(result['exit'],0)
                self.assertEqual(result['outside']or result['files'].get(RECORD),values['data'])

    def test_cleanup_removes_only_valid_owned_checkpoint_and_temp_before_success(self):
        result=run('''checkpoint_phase restoration
printf 'PERL5423_ROOT_PHASE_V1 %s restoration\n' "$nonce" > "$D/.root-phase.checkpoint.tmp"
chmod 600 "$D/.root-phase.checkpoint.tmp"
clear_root_phase
''')
        self.assertEqual(result['exit'],0);self.assertFalse(result['files']);self.assertFalse(result['modes'])
        result=run('if clear_root_phase;then exit 9;fi',data=record(),alias='symlink')
        self.assertEqual(result['exit'],0);self.assertEqual(result['outside'],record())

    def test_timeout_diagnostic_is_outside_frame_and_preserves_own_HOLD_reason(self):
        result=run('trap finish EXIT\nwait_for_case installed',probe=True,data=record())
        self.assertEqual(result['exit'],1)
        line=b'PERL5423_LAST_ROOT_PHASE '+NONCE.encode()+b' installed_metadata\n'
        self.assertEqual(result['stdout'].count(line),1)
        self.assertLess(result['stdout'].index(line),result['stdout'].index(b'PERL5423_PROBE_BEGIN'))
        self.assertIn(b'STATUS=HOLD\nFAILURE_SOURCE=PROBE\nFAILED_PHASE=install_ready_timeout\n',result['stdout'])
        self.assertNotIn(b'FUNCTIONAL=PASS',result['stdout']);self.assertNotIn(b'COMMANDS=PASS',result['stdout'])

    def test_missing_unsafe_partial_foreign_or_drifting_checkpoint_is_ignored(self):
        cases=[{},dict(data=record(nonce='b'*32)),dict(data=record('unknown')),dict(data=record()[:-1]),dict(data=record()+b'EXTRA\n'),
               dict(data=record().replace(b'installed_metadata',b'installed_\0metadata')),dict(data=record(),mode=0o600),
               dict(data=record(),mode=0o666),dict(data=record(),owner=1000),dict(data=record(),alias='symlink'),
               dict(data=record(),alias='hardlink'),dict(alias='fifo'),dict(data=b'X'*129),dict(data=record(),drift=True)]
        for values in cases:
            with self.subTest(values=values):
                result=run('trap finish EXIT\nwait_for_case installed',probe=True,**values)
                self.assertEqual(result['exit'],1);self.assertIn(b'FAILED_PHASE=install_ready_timeout\n',result['stdout'])
                self.assertNotIn(b'PERL5423_LAST_ROOT_PHASE',result['stdout'])

    def test_no_diagnostic_for_Root_HOLD_or_a_non_timeout_ready_path(self):
        summary=(f'PERL5423_RESTORED_BEGIN {NONCE}\nSTATUS=HOLD\nFAILED_PHASE=install\nEXIT_STATUS=1\nPERL5423_RESTORED_END {NONCE}\n').encode()
        result=run('trap finish EXIT\nwait_for_case installed',probe=True,data=record(),summary=summary)
        self.assertEqual(result['stdout'],b'\n'+summary);self.assertEqual(result['exit'],1)
        result=run('''install -d -m755 "$O"
printf '%s\n' "$nonce" > "$O/installed"
wait_for_case installed
printf READY
''',probe=True,data=record())
        self.assertEqual((result['exit'],result['stdout']),(0,b'READY'))

    def test_source_boundary_hooks_cleanup_order_and_no_cap_or_failure_trap_change(self):
        root=(HERE/'guest/root.sh').read_text();probe=(HERE/'guest/probe.sh').read_text()
        phases=re.findall(r'^\s*checkpoint_phase ([a-z_]+)$',root,re.M)
        self.assertLessEqual(len(phases),20);self.assertTrue(set(phases)<=PHASES);self.assertIn('installed_metadata',phases)
        clear=root.index('\nclear_root_phase\n');success=root.index("printf 'PERL5423_RESTORED_BEGIN %s\\nSTATUS=PASS")
        self.assertLess(clear,success);self.assertLess(root.rindex('checkpoint_phase restoration'),clear)
        self.assertEqual(probe.count('relay_last_root_phase || :'),1)
        timeout=probe.index('if (( SECONDS >= end ));then');call=probe.index('relay_last_root_phase || :');self.assertLess(timeout,call)
        checkpoint_helpers=root[root.index('write_root_phase()'):root.index('# Fixed failure labels only;')]+root[root.index('clear_root_phase() {'):root.index('finish() {')]
        self.assertNotIn('sync',checkpoint_helpers)
        self.assertIn('probe_wait_seconds',probe);self.assertNotIn('probe_wait_seconds=',probe)
        self.assertIn('FAILED_PHASE=%s\\nEXIT_STATUS=%s',root[root.index('finish() {'):root.index('trap finish EXIT')])

if __name__=='__main__':unittest.main(verbosity=2)
