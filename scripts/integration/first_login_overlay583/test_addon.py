# SPDX-License-Identifier: MIT
"""Fenced first-login staging and guest hook controls."""

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STAGE=load('addon_stage',HERE/'stage.py')
GUEST=load('addon_guest',HERE/'guest.py')
TARGET=load('addon_target',HERE/'target.py')
TRIAL=load('addon_overlay583_trial',HERE.parents[2]/'scripts/install/overlay583_trial/trial.py')
SIGNER='1'*40
REHEARSAL=dict(fingerprint=SIGNER,created=1794701213,expires=1794787613,test_only=True)


def deny(event,_args):
    if event.startswith(('subprocess.','socket.','os.exec','os.fork','os.posix_spawn')) or event in {'os.system','os.kill'}:
        raise AssertionError('unexpected lifecycle fixture actor: '+event)


def digest(body):
    return sha256(body).hexdigest()


class GuestHook(unittest.TestCase):
    def test_pinned_target_profile_and_ordinary_callback(self):
        paths=[]
        journey=SimpleNamespace(TEMPLATE_HASHES={'fish0.1.0-1-zsh0.1.0-1':{'fish/config.fish':'fixture'}},
                                run=lambda *args,**kwargs:paths.append((args,kwargs)) or {'status':'PASS'})
        callback=object()
        home=Path('/run/caa-first-login-overlay583/home')
        self.assertEqual(TARGET.run_installed(journey,home,callback,29083,812),{'status':'PASS'})
        args,kwargs=paths[0]
        self.assertEqual(args[1:],(home,callback,29083,812))
        self.assertEqual(kwargs['label'],'first-login-overlay583')
        self.assertEqual(args[0]['first_login'],'/usr/bin/cachy-asahi-first-login')
        self.assertEqual(args[0]['setup'],'/usr/bin/cachy-asahi-setup')
        self.assertEqual(args[0]['template_profile'],'fish0.1.0-1-zsh0.1.0-1')
        self.assertEqual(args[0]['user'],TARGET.ACCOUNT)

    def fixture(self, root, *, signer=SIGNER, drift=False, expired=False):
        self.steps=[]
        self.current=b'base-fixture 1-1\n'
        before=self.current
        after=before+b'cachy-asahi-first-login 0.1.0-2\n'
        target=root/'target'
        target.mkdir()
        trust=root/'trust';trust.mkdir()
        cfg=root/'pacman.conf';cfg.write_text('[options]\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
        for path in (target/'run', root/'cache'):
            path.mkdir()
        programs={name:('installed '+name).encode() for name in GUEST.PROGRAMS}
        pins={field:digest(programs[name]) for name,field in GUEST.PROGRAMS.items()}
        stage=SimpleNamespace(PROVENANCE=STAGE.PROVENANCE,SIGNER=STAGE.SIGNER,ARCHIVE=STAGE.ARCHIVE,
                              PUBLIC=STAGE.PUBLIC,**pins)
        paths=SimpleNamespace(WORK=root,CONFIG=cfg,ordinary=TRIAL.ordinary,need=TRIAL.need,read=TRIAL.read,
                              pin=TRIAL.pin,sorted_rows=TRIAL.sorted_rows,target_api_mounts=lambda *args:None)
        user_state={'.zshrc':b'fixture user edit\n','.config/fish/config.fish':b'fixture user edit config\n'}

        def command(step,argv,timeout,contents=None):
            self.steps.append(step)
            if argv[0]=='/usr/bin/pacman':
                self.assertEqual(argv[argv.index('--root')+1], str(target))
                self.assertEqual(argv[argv.index('--gpgdir')+1],str(trust))
                self.assertEqual(argv[argv.index('--logfile')+1],str(root/'first-login-addon-pacman.log'))
                self.assertNotIn('--noscriptlet',argv)
            if argv[-1]=='--query':
                return self.current
            if step=='first-login-verify-signature':
                outcome='EXPKEYSIG' if expired else 'GOODSIG'
                return (f'[GNUPG:] {outcome} {signer[-16:]} fixture\n'
                        f'[GNUPG:] VALIDSIG {signer} 2026-11-15 1794701213 0 4 0 1 10 00 {signer}\n').encode()
            if step=='first-login-install':
                self.assertEqual(argv[-1],str(GUEST.SUPPLEMENT/STAGE.ARCHIVE))
                self.current=after
                for name,raw in programs.items():
                    path=target/name
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(raw)
            if step=='first-login-installed-journey':
                self.assertEqual(argv[:4],['/usr/bin/chroot',str(target),'/usr/bin/python3','-I'])
                self.assertEqual(argv[-2],str(GUEST.TARGET_WORK/'target.py'))
                home=(target/GUEST.TARGET_WORK.relative_to('/')/'home')
                for name,raw in user_state.items():
                    path=home/name
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(raw)
                return json.dumps(dict(status='PASS',command_count=27,shell_startups=10,recovery_confirmed=True,
                                       final_components_deactivated=True,user_edit_preservation={n:digest(v) for n,v in user_state.items()})).encode()
            if step=='first-login-uninstall':
                self.current=before
                for name in programs:
                    (target/name).unlink()
                if drift:
                    (target/GUEST.TARGET_WORK.relative_to('/')/'home/.zshrc').write_bytes(b'damaged user')
            return b''

        files={name:b'fixture' for name in (STAGE.PUBLIC,'target.py','journey.py','owned_process.py')}
        return (paths,stage,target,before,after,files,'a'*32,{'GNUPGHOME':str(trust)},command,REHEARSAL)

    def test_signed_single_package_and_retained_native_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=GUEST.exercise(*self.fixture(Path(tmp)))
        self.assertEqual(result['status'],'PASS_ARM16K_OVERLAY583_FIRST_LOGIN_INSTALLED_LIFECYCLE')
        self.assertEqual(result['before'],result['after_removal'])
        self.assertNotEqual(result['before'],result['installed'])
        self.assertEqual(result['native_arm_build'],'NOT RUN')
        self.assertLess(self.steps.index('first-login-verify-signature'),self.steps.index('first-login-install'))
        self.assertLess(self.steps.index('first-login-installed-journey'),self.steps.index('first-login-uninstall'))

    def test_wrong_test_signer_stops_before_new_trust_or_install(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError,'exact selected TEST detached'):
            GUEST.exercise(*self.fixture(Path(tmp),signer='2'*40))
        self.assertNotIn('first-login-trust-fixture',self.steps)
        self.assertNotIn('first-login-install',self.steps)

    def test_expired_key_stops_before_trust_even_with_validsig(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError,'exact selected TEST detached'):
            GUEST.exercise(*self.fixture(Path(tmp),expired=True))
        self.assertNotIn('first-login-trust-fixture',self.steps)
        self.assertNotIn('first-login-install',self.steps)

    def test_configuration_edits_survive_alpm_remove_gate(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError,'preserve the exact user edits'):
            GUEST.exercise(*self.fixture(Path(tmp),drift=True))
        self.assertNotIn('first-login-remove-fixture-user',self.steps)

    def test_wrong_overlay_lock_refuses_before_staging_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'target.lock').write_text('wrong-overlay 1-1\n')
            nothing=root/'never-opened'
            out=root/'staged'
            with self.assertRaisesRegex(ValueError,'Expected file length or digest differs'):
                STAGE.prepare(staging=root,preflight=nothing,archive=nothing,signature=nothing,public_key=nothing,output=out)
            self.assertFalse(out.exists())

    def test_data_only_stage_module_can_import_from_short_guest_path(self):
        module=type(STAGE)('mounted_stage')
        module.__file__='/trial-code/first-login/stage.py'
        raw=(HERE/'stage.py').read_bytes()
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
        self.assertEqual(module.PROVENANCE,STAGE.PROVENANCE)


if __name__=='__main__':
    sys.addaudithook(deny)
    unittest.main(verbosity=2)
