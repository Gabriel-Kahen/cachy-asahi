"""Host shell controls for log routing; never execute the OCI entrypoint."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PhaseLogRetentionTests(unittest.TestCase):
    def run_build_command(self, failure='', source=None):
        source = source or (ROOT / 'scripts/build/container-entry-v2.sh').read_text()
        commands = [line for line in source.splitlines() if 'makepkg --cleanbuild ' in line]
        self.assertEqual(len(commands), 1)
        # Run only this invocation in a temporary directory. The fake models
        # LOGDEST routing and makepkg's cwd cleanup glob, with an empty prepare
        # log and failure before later phases exist. This is a host control.
        fake = r'''
makepkg() {
  [[ "$*" == '--cleanbuild --clean --force --log --noconfirm' ]] || return 92
  local phase destination=${LOGDEST:-$PWD}
  for phase in prepare build check package; do
    : > "$destination/fixture-1-1-aarch64-$phase.log"
    if [[ $phase != prepare ]]; then
      printf '%s\n' "simulated $phase output" > "$destination/fixture-1-1-aarch64-$phase.log"
    fi
    [[ ${FAIL_PHASE:-} != "$phase" ]] || return 17
  done
  rm -rf -- "$PWD/src" "$PWD/pkg"
  rm -f -- "$PWD"/fixture-1-1-aarch64-{prepare,build,check,package}.log*
}
'''
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); out = root/'out'; work = root/'work'
        out.mkdir(); work.mkdir(); (work/'src').mkdir(); (work/'pkg').mkdir()
        command = commands[0].replace('LOGDEST=/out ', 'LOGDEST="$1" ')
        result = subprocess.run(['bash', '-euc', fake+'\n'+command, 'phase-retention-control', str(out)],
                                cwd=work, env={'PATH':'/usr/bin:/bin', 'FAIL_PHASE':failure},
                                capture_output=True, timeout=10)
        return result, out, work

    def test_success_preserves_all_phases_and_cleanup(self):
        result,out,work = self.run_build_command()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual({p.name for p in out.iterdir()},
                         {'fixture-1-1-aarch64-'+phase+'.log' for phase in ('prepare','build','check','package')})
        self.assertEqual((out/'fixture-1-1-aarch64-prepare.log').read_bytes(),b'')
        self.assertIn(b'check output',(out/'fixture-1-1-aarch64-check.log').read_bytes())
        self.assertFalse((work/'src').exists()); self.assertFalse((work/'pkg').exists())
        self.assertFalse(list(work.glob('*.log')))

    def test_failure_preserves_partial_logs_and_exact_exit(self):
        result,out,work = self.run_build_command('check')
        self.assertEqual(result.returncode,17)
        self.assertEqual({p.name for p in out.iterdir()},
                         {'fixture-1-1-aarch64-'+phase+'.log' for phase in ('prepare','build','check')})
        self.assertTrue((work/'src').is_dir())
        self.assertFalse((out/'fixture-1-1-aarch64-package.log').exists())

    def test_old_routing_reproduces_loss(self):
        source=(ROOT/'scripts/build/container-entry-v2.sh').read_text()
        result,out,work = self.run_build_command(source=source.replace('LOGDEST=/out makepkg --cleanbuild','makepkg --cleanbuild'))
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertFalse(list(out.iterdir())); self.assertFalse(list(work.glob('*.log')))


if __name__ == '__main__': unittest.main()
