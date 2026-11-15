# SPDX-License-Identifier: MIT
"""Exact historical7 -> candidate8 -> historical7 host analogue; no native role."""
import importlib.util
import json
import os
from pathlib import Path
import shutil

HERE = Path('/opt/python314-inputs')
spec = importlib.util.spec_from_file_location('completed_downgrade_actor', HERE / 'downgrade_actor.py')
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
need, sha = previous.need, previous.sha
OLD = 'python-3.14.7-1-x86_64.pkg.tar.zst'
OLD_SHA = '8a350ce53aae01ae687f043b301931e411bf06333ba480b42b3b5432a0e6c79b'
SIG_SHA = 'ff4000fab52654e77a2de73ff242ea809b0b4fd2e17951a8375f575180c1ecae'


class Upgrade(previous.Trial):
    def caller_state(self):
        return {p.relative_to(self.caller).as_posix(): previous.repository.owned_state(
                    self.caller, p.relative_to(self.caller).as_posix()) for p in sorted(self.caller.rglob('*'))}

    def runtime_probe(self, label, micro, caller=False):
        base = self.target / 'usr'
        tcl = [p for p in (base / 'lib/tcl8.6', base / 'share/tcl8.6') if (p / 'init.tcl').is_file()]
        need(len(tcl) == 1, 'private Tcl script path required')
        env = dict(self.env, LD_LIBRARY_PATH=str(base / 'lib'), TCL_LIBRARY=str(tcl[0]))
        old_env = self.runner.env
        self.runner.env = env
        try:
            executable = (self.caller / 'venv/bin/python3.14') if caller else base / 'bin/python3.14'
            code = """import sys,json,hashlib,ssl,sqlite3,ctypes,decimal,zlib,bz2,lzma,_tkinter,tkinter,sysconfig
from pathlib import Path
base,prefix,micro,tcl=Path(sys.argv[1]),Path(sys.argv[2]),int(sys.argv[3]),Path(sys.argv[4])
assert sys.version_info[:3]==(3,14,micro) and Path(sys.prefix)==prefix and Path(sys.base_prefix)==base
assert Path(sysconfig.__file__).is_relative_to(base) and Path(_tkinter.__file__).is_relative_to(base)
raw=b'candidate upgrade caller'*64
for m in (zlib,bz2,lzma): assert m.decompress(m.compress(raw))==raw
assert decimal.Decimal('1.25')*4==5
c=sqlite3.connect(':memory:'); assert c.execute('select 42').fetchone()==(42,); c.close()
assert ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) and ctypes.CDLL(None)
t=tkinter.Tcl(); assert t.eval('info patchlevel')=='8.6.16' and t.eval('info exists tk_version')=='0'
assert Path(t.eval('info library'))==tcl
maps=sorted({x.split()[-1] for x in Path('/proc/self/maps').read_text().splitlines() if 'libpython' in x})
assert maps==[str(base/'lib/libpython3.14.so.1.0')]
result=dict(python=sys.version,prefix=sys.prefix,base_prefix=sys.base_prefix,executable=sys.executable,Tcl=t.eval('info patchlevel'),Tk_loaded=False,mapped_library=maps)
if prefix!=base:
 import caller_state,historical_caller
 compiled,runtime,value=historical_caller.identity()
 assert compiled=='3.14.7' and runtime==sys.version and value==4 and caller_state.VALUE=='operator-owned sentinel42'
 assert Path(historical_caller.__file__).is_relative_to(prefix)
 result.update(compiled_extension=compiled,extension_runtime=runtime,extension_sum=value,caller=caller_state.VALUE)
print(json.dumps(result,sort_keys=True))
"""
            prefix = self.caller / 'venv' if caller else base
            return json.loads(self.command(label, [executable, '-I', '-B', '-c', code, base, prefix, str(micro), tcl[0]]))
        finally:
            self.runner.env = old_env

    def create_caller(self):
        self.caller = self.scratch / 'caller'
        self.caller.mkdir()
        base = self.target / 'usr'
        old_env = self.runner.env
        self.runner.env = dict(self.env, LD_LIBRARY_PATH=str(base / 'lib'))
        try:
            self.command('historical-venv-create', [base / 'bin/python3.14', '-I', '-B', '-m', 'venv',
                                                 '--symlinks', '--without-pip', self.caller / 'venv'])
            site = self.caller / 'venv/lib/python3.14/site-packages'
            module = site / 'caller_state.py'
            module.write_text("VALUE='operator-owned sentinel42'\n")
            module.chmod(0o644)
            os.chown(module, 1000, 1000)
            self.command('historical-header-extension-compile', ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-shared', '-fPIC', '-I' + str(base / 'include/python3.14'), HERE / 'caller.c', '-o',
                site / 'historical_caller.cpython-314-x86_64-linux-gnu.so'])
        finally:
            self.runner.env = old_env

    def run(self):
        self.result['guard'] = previous.guard()
        need(sha(HERE / OLD) == OLD_SHA and sha(HERE / (OLD + '.sig')) == SIG_SHA, 'historical material changed')
        need((HERE / 'historical-gates.txt').read_text().strip() ==
             'PASS public Arch signature and declared dependency closure for exact python3.14.7-1',
             'public signature/dependency gate missing; refuse TEST signing')
        current = previous.metadata(HERE / 'baseline' / previous.BASELINE)
        historical, candidate = previous.metadata(HERE / OLD), previous.metadata(HERE / previous.ARCHIVE)
        need(historical['info']['pkgver'] == ['3.14.7-1'] and candidate['info']['pkgver'] == ['3.14.8-1.1'], 'exact versions required')
        self.copy_base()
        for name, target in {'bin': 'usr/bin', 'sbin': 'usr/bin', 'lib': 'usr/lib', 'lib64': 'usr/lib'}.items():
            (self.target / name).symlink_to(target)
        options = '[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nParallelDownloads = 1\n'
        self.config.write_text(options)
        self.query_config.write_text(options)
        shutil.copyfile(self.config, self.out / 'TEST-pacman.conf')
        shutil.copyfile(self.query_config, self.out / 'TEST-query-pacman.conf')
        # Public verification above must precede these ephemeral TEST identities.
        for role, usage in [('signer', 'sign'), ('verifier', 'cert')]:
            self.key(role, usage)
            (self.keys[role]['home'] / 'gpg.conf').write_text('no-auto-key-retrieve\nauto-key-locate clear\n')
        source_inventory = self.inventory('copied-image-inventory')
        need(source_inventory['python'] == '3.14.9-1', 'unexpected copied provisioning version')
        self.installed(current)
        packages = self.scratch / 'packages'
        packages.mkdir()
        old, new = packages / OLD, packages / previous.ARCHIVE
        for source, target in [(HERE / OLD, old), (HERE / previous.ARCHIVE, new)]:
            shutil.copyfile(source, target)
            self.sign(target, 'signer')
        self.trust('signer')
        self.pacman('setup-exact-historical-baseline', ['-U', '--noscriptlet', old])
        baseline = dict(source_inventory, python='3.14.7-1')
        need(self.inventory('historical-inventory') == baseline, 'historical setup changed another package')
        self.installed(historical)
        self.retired(current, historical)
        operator = self.target / 'etc/python314-operator.conf'
        operator.write_text('operator edited baseline7 configuration\n')
        operator.chmod(0o640)
        startup = self.target / 'home/operator/.config/python/startup.py'
        startup.parent.mkdir(parents=True)
        startup.write_text('# keep operator startup through upgrade and rollback\n')
        startup.chmod(0o644)
        os.chown(startup, 1000, 1000)
        need('owned by bash ' in self.pacman('vendor-ownership', ['-Qo', self.target / 'usr/bin/bash']), 'vendor sentinel ownership')
        sentinels = self.sentinels()
        self.create_caller()
        preserved = self.caller_state()
        before = self.runtime_probe('baseline7-runtime', 7)
        before_caller = self.runtime_probe('baseline7-caller', 7, caller=True)
        self.pacman('historical7-to-candidate8-upgrade', ['-U', '--noscriptlet', new])
        upgraded = dict(baseline, python='3.14.8-1.1')
        need(self.inventory('upgraded-inventory') == upgraded, 'upgrade changed another package')
        self.installed(candidate)
        self.retired(historical, candidate)
        full = self.smoke('candidate8')
        after_caller = self.runtime_probe('candidate8-preserved-caller', 8, caller=True)
        need(self.caller_state() == preserved and self.sentinels() == sentinels, 'upgrade changed preserved caller state')
        self.pacman('retained-historical7-rollback', ['-U', '--noscriptlet', old])
        need(self.inventory('rollback-inventory') == baseline, 'rollback did not restore full baseline inventory')
        self.installed(historical)
        self.retired(candidate, historical)
        restored = self.runtime_probe('rollback7-runtime', 7)
        restored_caller = self.runtime_probe('rollback7-preserved-caller', 7, caller=True)
        need(self.caller_state() == preserved and self.sentinels() == sentinels, 'rollback changed preserved caller state')
        for name, value in [('historical-payload.json', historical), ('candidate-payload.json', candidate),
                            ('caller-state.json', preserved)]:
            (self.out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
        for name in ('public-signature-3147.txt', 'closure-3147.txt', 'historical-gates.txt', OLD, OLD + '.sig'):
            shutil.copyfile(HERE / name, self.out / name)
        self.result.update(status='PASS exact historical x86_64 Python3.14.7 -> candidate3.14.8 upgrade and rollback',
            provisioning_inventory=source_inventory, baseline_inventory=baseline, upgraded_inventory=upgraded,
            restored_inventory=baseline, baseline7=before, baseline7_caller=before_caller,
            candidate8_full_runtime=full, candidate8_preserved_caller=after_caller,
            rollback7=restored, rollback7_preserved_caller=restored_caller,
            sentinels=sentinels, preserved_caller_state='PASS bytes/modes/uid/gid/symlinks unchanged across7/8/7',
            historical_archive_sha256=OLD_SHA, historical_public_signature_sha256=SIG_SHA,
            historical_payload_nodes=len(historical['payload']), candidate_payload_nodes=len(candidate['payload']),
            holds=['host analogue only; not Asahi ARM3.14.7 upgrade acceptance',
                   'native ARM/16K/M2/GUI/performance/source/legal/production trust/release remain unqualified',
                   'initial3.14.9->3.14.7 setup is separate from tested3.14.7->3.14.8 upgrade',
                   'existing downgrade/core/fullTk/ABI/env evidence unchanged'])


if __name__ == '__main__':
    # Reuse the unchanged actor's finite deadline, guarded entry and checked TEST
    # agent/private-home cleanup; only this loaded module's concrete trial varies.
    previous.Trial = Upgrade
    raise SystemExit(previous.main())
