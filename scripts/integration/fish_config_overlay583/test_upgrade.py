# SPDX-License-Identifier: MIT
"""Actor-free Fish package and real nonprivileged host shell fixtures."""

from base64 import b64encode
from io import BytesIO
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
from unittest.mock import patch
import unittest

HERE=Path(__file__).resolve().parent
TREE=HERE.parents[2]
BASE=Path("/home/gabe/Documents/ChatGPT/cachy-asahi-staging-install-lock-20261117-overlay583")
PRE=BASE.parent/"cachy-asahi-staging-install-lock-20261117-preflight583-results/retained583.json"
HELD=TREE.parent/"cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-fish70-r11-native-result-r127-r1"
NONCE="9"*32
SUCCESSOR=dict(bytes=5516,sha256="6dee81130f3ba3e570791cf079d2152893461ec27fa6e2e34a3d614986f9a949")


def load(path):
    spec=importlib.util.spec_from_file_location(path.stem,path)
    app=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


T=load(TREE/"scripts/install/overlay583_trial/trial.py")
O=load(HERE/"operands.py")
G=load(HERE/"guest.py")
P=load(HERE/"probe.py")
B=load(HERE/"bridge.py")


def tar_leaf(raw, name):
    with tarfile.open(fileobj=BytesIO(raw),mode="r:xz") as body:
        row=body.getmember(name)
        assert row.isreg() and 0<row.size<=128*1024
        return body.extractfile(row).read()


class FishUpgrade(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=T.read(BASE/O.REPO/O.PREVIOUS,O.PIN_OLD,cap=64*1024)
        cls.closure=T.read(HELD/"Root-independent-native-pair.ACTUAL.json",cap=8*1024)
        assert T.pin(cls.closure)["sha256"]=="7fd4cb030ee33f586900b5e34a17f0c8f241e7c4e08de576796ef3188545c419"
        cls.hold=T.decode(cls.closure)
        assert cls.hold["native_pair"]=="HOLD" and cls.hold["required_missing"]
        evidence=T.read(HELD/"public-evidence.Original.archive",cls.hold["archive"],cap=2*1024**2)
        prefix="fish02-owned-public-ftkjq_ka/evidence/"
        with tarfile.open(fileobj=BytesIO(evidence),mode="r:gz") as body:
            cls.members=[]
            for i in (1,2):
                row=body.getmember(prefix+f"build-{i}/artifacts/"+O.SUCCESSOR)
                assert row.isreg() and row.size==SUCCESSOR["bytes"]
                cls.members.append(body.extractfile(row).read())
        assert all(T.pin(raw)==SUCCESSOR for raw in cls.members)
        cls.raw=cls.members[0]
        cls.base=T.read(BASE/"target.lock",O.TARGET,cap=64*1024)
        _,cls.updated=O.inventories(T,cls.base)

    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="fish-upgrade-isolated-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.signer="AB1234567890AB1234567890AB1234567890AB12"
        self.now=int(time.time())
        # These are explicitly model records. The retained R127 is held.
        self.model=dict(kind=O.PAIR_KIND,issuer="Root",status="PASS",source=O.SOURCE,run=O.RUN,
             architecture="aarch64",package_architecture="any",closure=T.pin(b"synthetic qualifying receipt"),
             builds=[dict(build=i,archive=SUCCESSOR,clean=True,checks="PASS") for i in (1,2)])
        self.inventory=O.baseline(T,BASE,PRE)

    def test_exact_signed_predecessor_and_held_r127_package_payloads(self):
        self.assertEqual(self.inventory["before"],self.inventory["restored"])
        self.assertEqual(self.inventory["upgraded"],dict(bytes=11450,sha256="891673a2bc003f637b7252e9d9c9ce0d2cccbd09d2efa83f86f4b418782ef617"))
        actual=O.package(T,self.raw,O.NEW)
        old=self.inventory["predecessor"]["payload"]
        self.assertEqual({name for name in old if old[name]!=actual[name]},{O.CONFIG})
        with self.assertRaisesRegex(ValueError,"qualified matching R127"):
            O.qualification(T,T.encoded(self.hold),SUCCESSOR)

    def fixture_stage(self,*,single=False,secret=False,held=False):
        a,b,q,signature,key=[self.root/name for name in ("build1.xz","build2.xz","pair.json","test.sig","test.gpg")]
        for path,raw in zip((a,b),self.members,strict=True):
            path.write_bytes(raw)
        q.write_bytes(T.encoded(self.hold if held else self.model))
        signature.write_bytes(bytes([0xc2,1,0]))
        key.write_bytes(bytes([0xc5 if secret else 0xc6,1,0,0xcd,1,0,0xc2,1,0]))
        folder=self.root/"MODEL-NOT-QUALIFIED"
        data=O.stage(T,staging=BASE,preflight=PRE,archive=a,matching_archive=a if single else b,qualified=q,
            qualified_sha256=T.pin(q.read_bytes())["sha256"],signature=signature,public_key=key,signer=self.signer,output=folder)
        return folder,data

    def test_stage_rejects_same_inode_held_pair_and_private_key_packet(self):
        with self.assertRaisesRegex(ValueError,"two retained"):
            self.fixture_stage(single=True)
        with self.assertRaisesRegex(ValueError,"qualified matching R127"):
            self.fixture_stage(held=True)
        with self.assertRaisesRegex(ValueError,"public TEST"):
            self.fixture_stage(secret=True)
        folder,packet=self.fixture_stage()
        self.assertEqual(O.check_stage(T,folder,packet["receipt"]["sha256"],sources=HERE),packet)
        self.assertIsNone(packet["Root_authority"])
        self.assertEqual(packet["installation"],"NOT RUN")

    def test_production_projection_is_exact_bounded_version_only(self):
        folder,packet=self.fixture_stage()
        result=B.passive_plan(T,staging=BASE,preflight=PRE,supplement=folder,
                              supplement_sha256=packet["receipt"]["sha256"],nonce=NONCE)
        self.assertIsNone(result["host_authority"])
        plan=result["guest_plan"]
        self.assertEqual(plan["kind"],G.PLAN_KIND)
        self.assertEqual(plan["operations"],T.guest_plan(plan["packet"],NONCE)["operations"])
        self.assertEqual(plan["fish_upgrade"]["receipt"],packet["receipt"])
        self.assertEqual(plan["packet"]["target"],O.TARGET)

    def test_local_db_allows_only_the_expected_install_date_to_change(self):
        target=self.root/"target"
        root=target/"var/lib/pacman/local"
        root.mkdir(parents=True)
        (root/"ALPM_DB_VERSION").write_text("9\n")
        for name,ver in T.canonical_lock(self.base,583).items():
            directory=root/f"{name}-{ver}"
            directory.mkdir()
            (directory/"files").write_text("%FILES%\nusr/share/fixture\n\n")
            (directory/"desc").write_text("%NAME%\n"+name+"\n\n%INSTALLDATE%\n100\n\n%REASON%\n0\n")
        path=root/f"{O.PACKAGE}-{O.OLD}/desc"
        original=path.read_bytes()
        with patch.object(T,"TARGET",target):
            initial=G.db_snapshot(T,O,O.OLD)
            path.write_bytes(original.replace(b"100",b"200"))
            self.assertEqual(G.db_snapshot(T,O,O.OLD),initial)
            path.write_bytes(original.replace(b"%REASON%\n0",b"%REASON%\n1"))
            changed=G.db_snapshot(T,O,O.OLD)
            self.assertEqual(changed["unchanged_packages"],initial["unchanged_packages"])
            self.assertNotEqual(changed["selected_package"],initial["selected_package"])
            other=next(f/"files" for f in root.iterdir() if f.is_dir() and not f.name.startswith(O.PACKAGE+"-"))
            other.write_text("unexpected altered original ownership")
            self.assertNotEqual(G.db_snapshot(T,O,O.OLD)["unchanged_packages"],initial["unchanged_packages"])

    def test_same_real_setup_user_bytes_and_fish_startup_old_new_old(self):
        if os.getuid()==0:
            self.skipTest("The host source control requires an ordinary user")
        home=self.root/"home"
        (home/".config/fish").mkdir(parents=True,mode=0o700)
        home.chmod(0o700)
        user=home/P.USER_CONFIG
        user.write_bytes(P.USER_BYTES)
        user.chmod(0o600)
        templates=self.root/"installed/share/cachy-asahi"
        (templates/"fish").mkdir(parents=True)
        fixture=templates/"fish/config.fish"
        fixture.write_bytes(tar_leaf(self.original,O.CONFIG))
        setup_body=T.read(BASE/O.REPO/"cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz",
            dict(bytes=33900,sha256="8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47"),cap=64*1024)
        setup=self.root/"setup"
        setup.write_bytes(tar_leaf(setup_body,"usr/bin/cachy-asahi-setup"))
        env={"PATH":"/usr/bin:/bin","HOME":str(home),"XDG_CONFIG_HOME":str(home/".config"),
             "XDG_STATE_HOME":str(home/".local/state"),"XDG_DATA_HOME":str(home/".local/share"),
             "XDG_CACHE_HOME":str(home/".cache"),"LC_ALL":"C.UTF-8","TERM":"dumb"}
        process=subprocess.run([sys.executable,"-I","-B",str(setup),"activate","--components","fish","--apply",
            "--home",str(home),"--template-root",str(templates)],env=env,cwd=home,capture_output=True,timeout=20)
        self.assertEqual(process.returncode,0,process.stderr)
        activated=user.read_bytes()
        self.assertIn(P.USER_BYTES,activated)
        self.assertIn(str(fixture).encode(),activated)
        for phase,body in zip(P.PHASES,(self.original,self.raw,self.original),strict=True):
            fixture.write_bytes(tar_leaf(body,O.CONFIG))
            work=home/phase
            process=subprocess.run(["/usr/bin/fish","--private","--interactive","--command",P.SCRIPT,str(work),str(os.getuid())],
                env=env,cwd=home,capture_output=True,timeout=15)
            self.assertEqual(process.returncode,0,process.stderr)
            observed=P.receipt(process.stdout,work,os.getuid(),expect_local=(phase=="upgraded"))
            self.assertEqual(observed["local_selected"],phase=="upgraded")
            self.assertTrue((work/"space directory").is_dir())
            self.assertEqual(user.read_bytes(),activated)
            self.assertEqual(user.stat().st_mode&0o777,0o600)

    @staticmethod
    def status(signer, when):
        return (f"[GNUPG:] GOODSIG {signer[-16:]} Model TEST\n"
                f"[GNUPG:] VALIDSIG {signer} time {when} 0 4 0 22 8 00 {signer}\n").encode()

    def test_independent_reader_rejects_swapped_probe_and_expired_signature(self):
        _,stage=self.fixture_stage()
        states={name:dict(unchanged_packages=T.pin(b"unchanged"),selected_package=T.pin(name.encode()))
                for name in ("before","upgraded")}
        states["restored"]=states["before"]
        phases=("before","upgraded","restored")
        locks=dict(zip(phases,(self.base,self.updated,self.base),strict=True))
        key=dict(fingerprint=self.signer,created=self.now-10,expires=self.now+86400)
        output={f"fish-{name}":raw for name,raw in locks.items()}
        owner_paths={"/"+name for name in O.PAYLOAD}
        owner_paths|={str(path)+"/" for name in owner_paths for path in Path(name).parents if path!=Path("/")}
        owner=b"".join(f"{O.PACKAGE} {T.TARGET}{path}\n".encode() for path in sorted(owner_paths))
        probe={}
        for phase in phases:
            work=P.HOME/phase
            path=work/"space directory" if phase=="upgraded" else work/"lookup/space directory"
            raw=f"CAA_FISH_UPGRADE\t{P.UID}\t{path}\t{work/'lookup'}\n".encode()
            probe[phase]=P.receipt(raw,work,P.UID,expect_local=(phase=="upgraded"))
            output["fish-start-"+phase]=raw
            output[f"fish-{phase}-owners"]=owner
        output.update({"fish-verify-successor":self.status(self.signer,self.now),
                       "fish-verify-predecessor":self.status(G.OVERLAY_SIGNER,self.now),
                       "fish-preview-upgrade":f"{O.PACKAGE} {O.NEW}\n".encode(),
                       "fish-preview-restore":f"{O.PACKAGE} {O.OLD}\n".encode()})
        raw_alpm=(f"[time] [ALPM] upgraded {O.PACKAGE} ({O.OLD} -> {O.NEW})\n"
                  f"[time] [ALPM] downgraded {O.PACKAGE} ({O.NEW} -> {O.OLD})\n").encode()
        aggregate=dict(status=G.PASS,alpm=T.pin(raw_alpm),locks={name:T.pin(raw) for name,raw in locks.items()},db=states,probes=probe,
                       user_config={phase:T.pin(b"same user bytes") for phase in phases},key=key,
                       qualified_pair=stage["qualification"],page_size=16384,hardware="NOT RUN",Root_acceptance=None)
        def check():
            ledger=[dict(role=role,argv=argv,exit=0,stdout=b64encode(output.get(role,b"")).decode(),stderr="")
                    for role,argv in G.command_plan(T,O,P).items()]
            return G.readback(T,O,P,T.encoded(dict(commands=ledger,result=aggregate,alpm=b64encode(raw_alpm).decode("ascii"))),
                              baseline=self.base,stage=stage,held=False)
        self.assertEqual(check(),aggregate)
        original=output["fish-start-upgraded"]
        output["fish-start-upgraded"]=original.replace(b"/upgraded/space directory",b"/upgraded/lookup/space directory")
        with self.assertRaisesRegex(ValueError,"startup or CDPATH"):
            check()
        output["fish-start-upgraded"]=original
        output["fish-verify-successor"]=output["fish-verify-successor"].replace(b"GOODSIG",b"EXPKEYSIG")
        with self.assertRaisesRegex(ValueError,"signed Fish"):
            check()
        raw_alpm=raw_alpm.replace(b"[ALPM] downgraded",b"[ALPM] installed")
        aggregate["alpm"]=T.pin(raw_alpm)
        with self.assertRaisesRegex(ValueError,"original ALPM"):
            check()


if __name__=="__main__":
    unittest.main(verbosity=2)
