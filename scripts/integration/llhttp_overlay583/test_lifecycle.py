# SPDX-License-Identifier: MIT
"""Public read-only R124 planning inputs and model lifecycle controls."""

from base64 import b64encode
import importlib.util
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
BASE=Path("/home/gabe/Documents/ChatGPT/cachy-asahi-staging-install-lock-20261117-overlay583")
PRE=BASE.parent/"cachy-asahi-staging-install-lock-20261117-preflight583-results/retained583.json"
EVIDENCE=Path(os.environ.get("CAA_R124_EVIDENCE_DIR","/missing-r124-fixture"))
NONCE="8"*32


def load(path):
    spec=importlib.util.spec_from_file_location(path.stem,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C=load(ROOT/"install/overlay583_trial/controller.py")
T=C.T
O=load(HERE/"operands.py")
G=load(HERE/"guest.py")
P=load(HERE/"probe.py")


def deny(event,_):
    if event.startswith(("subprocess.","socket.","ctypes.dlopen")) or event in ("os.system","os.exec","os.fork"):
        raise AssertionError("No host package, library or VM actor in these fixtures")


@unittest.skipUnless(EVIDENCE.is_dir(),"Set CAA_R124_EVIDENCE_DIR for the public R124 planning fixture")
class Lifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=EVIDENCE/"Root-independent-r124-native-build-provides-closure.ACTUAL.json"
        closure_body=T.read(path,cap=8*1024)
        assert T.pin(closure_body)["sha256"]=="63acfbcb450d5a141ddbb1aba9241d4bc36c95047d696e461b9af398913f3692"
        cls.closure=T.decode(closure_body)
        assert cls.closure["native_pair"]=="NOT RUN"
        expected=dict(cls.closure["native_package"])
        name=expected.pop("name")
        with tarfile.open(EVIDENCE/"public-evidence.Original.archive","r:gz") as retained:
            member,=[item for item in retained if item.name.endswith("/evidence/build-1/artifacts/"+name)]
            assert member.isreg() and member.size==expected["bytes"]<=128*1024
            cls.body=retained.extractfile(member).read()
        assert T.pin(cls.body)==expected
        cls.payload=O.package(T,cls.body)
        cls.base=T.read(BASE/"target.lock",cap=64*1024)
        cls.after=T.sorted_rows(cls.base+f"{O.PACKAGE} {O.VERSION}\n".encode())

    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="llhttp-lifecycle-model-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.now=int(time.time())
        self.fpr="ABCDEF"+"1"*34
        self.key=dict(fingerprint=self.fpr,created=self.now-10,expires=self.now+86400,test_only=True)
        self.signed=(f"[GNUPG:] GOODSIG {self.fpr[-16:]} Mock TEST\n[GNUPG:] VALIDSIG {self.fpr} "
                     f"fixture-date {self.now} 0 4 0 22 8 00 {self.fpr}\n").encode()
        self.qualification=dict(kind=O.PAIR_KIND,issuer="Root",status="PASS",source="f"*40,run=1,
                                architecture="aarch64",structural_page_size=16384,closure=T.pin(b"model pair closure"),
                                builds=[dict(build=index,archive=T.pin(self.body),checks="PASS",clean=True)
                                        for index in (1,2)])

    def test_only_static_planning_on_retained_r124(self):
        self.assertEqual(T.pin(self.body)["bytes"],30828)
        self.assertEqual(set(self.payload),O.EXPECTED)
        self.assertEqual(self.payload[O.REAL]["pin"]["sha256"],
                         "2979156d5f739db2ce6058feab97c96dc8baeb21707d83e4c0cd8671ee281547")
        with self.assertRaises(ValueError):
            O.pair(T,T.encoded(self.closure),T.pin(self.body))

    def prepare(self, *, same=False, expired=False, secret=False):
        a,b=[self.root/name for name in ("build-1.xz","build-2.xz")]
        a.write_bytes(self.body)
        b.write_bytes(self.body)
        signed = self.signed.replace(b"GOODSIG",b"EXPKEYSIG") if expired else self.signed
        meta=(f"pub:u:255:22:678:{self.key['created']}:{self.key['expires']}:\n"
              f"fpr:::::::::{self.fpr}:\nuid:::::::::Mock LLHTTP TEST:\n").encode()
        signature,key,approval=[self.root/name for name in ("test.sig","test.gpg","test-pair.json")]
        signature.write_bytes(bytes([0xc2,1,0]))
        key.write_bytes(bytes([0xc5 if secret else 0xc6,1,0,0xcd,1,0,0xc2,1,0]))
        approval.write_bytes(T.encoded(self.qualification))
        stage=self.root/"modeled-stage-NO-AUTHORITY"
        with patch.object(O.subprocess,"run", side_effect=[SimpleNamespace(stdout=body) for body in (meta,signed)]):
            packet=O.prepare(T,staging=BASE,preflight=PRE,archive=a,matching_archive=a if same else b,qualification=approval,
                             qualification_sha256=T.pin(approval.read_bytes())["sha256"],signature=signature,public_key=key,
                             output=stage)
        return stage,packet

    def test_passive_stage_requires_distinct_exact_pair_and_current_test_signature(self):
        with self.assertRaisesRegex(ValueError,"Distinct retained"):
            self.prepare(same=True)
        with self.assertRaisesRegex(ValueError,"current TEST signature"):
            self.prepare(expired=True)
        with self.assertRaisesRegex(ValueError,"single Public TEST"):
            self.prepare(secret=True)
        stage,data=self.prepare()
        self.assertEqual(T.llhttp_selection(stage,data["receipt"]["sha256"]),data)
        self.assertEqual(data["after"],T.pin(self.after))
        self.assertIsNone(data["Root_authority"])
        self.assertEqual(data["installation"],"NOT RUN")
        with self.assertRaises(ValueError):
            O.pair(T,T.encoded(dict(self.qualification,builds=self.qualification["builds"][:1])),T.pin(self.body))

    @staticmethod
    def packet():
        pinned=T.choose(BASE,selected_lock=T.PINS)
        pre=T.read(PRE,cap=128*1024)
        return T.admit(pinned,pre,T.pin(pre))

    def test_main_controller_binds_only_exact_readonly_addon(self):
        stage,data=self.prepare()
        packet=self.packet()
        plan=T.selected_plan(packet,NONCE,llhttp=data)
        self.assertEqual(plan["kind"],T.LLHTTP_KIND)
        self.assertEqual(plan["operations"],T.guest_plan(packet,NONCE)["operations"])
        for options in (dict(first_login={}),dict(predecessor=self.root),
                        dict(lifecycle=True),dict(signature_recovery=True)):
            with self.assertRaisesRegex(ValueError,"only one"):
                T.selected_plan(packet,NONCE,llhttp=data,**options)
        self.assertEqual(T.evidence_names(plan)-T.evidence_names(T.guest_plan(packet,NONCE)),{"llhttp.json"})
        trimmed=dict(plan,packet=dict(packet,files={},trust={},aliases={}))
        worker=self.root/"trial.py"
        worker.write_bytes(b"fixture worker")
        (self.root/"staging").mkdir()
        (self.root/"staging/target.lock").write_bytes(self.base)
        packed=self.root/"packed"
        with patch.object(C,"runtime_payload",return_value={}):
            files,_,_=C.input_tree(self.root/"staging",worker,T.pin(worker.read_bytes()),T.encoded(trimmed),packed,llhttp=stage)
        self.assertEqual({name for name in files if name.startswith("inputs/")},{"inputs/target.lock"})
        self.assertEqual({name.split("/")[-1] for name in files if name.startswith("code/llhttp/")},
                         set(data["files"])|{"supplement.json"})
        self.assertTrue(all(path.stat().st_mode&0o777==0o444 for path in (packed/"code/llhttp").iterdir()))

    def run_lifecycle(self, *, wrong_signer=False, db_drift=False):
        stage,packet=self.prepare()
        sandbox=self.root/"target"
        (sandbox/"run").mkdir(parents=True)
        config=self.root/"pacman.conf"
        config.write_text("SigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n")
        calls=[]
        dig=packet["payload"][O.REAL]["pin"]["sha256"]
        snapshot=Mock(side_effect=[b"baseline",b"drift" if db_drift else b"baseline"])
        trial=SimpleNamespace(WORK=self.root,CONFIG=config,read=T.read,pin=T.pin,canonical_lock=T.canonical_lock,
                              need=T.need,sorted_rows=T.sorted_rows,decode=T.decode,target_api_mounts=lambda *_:None,
                              local_database_snapshot=snapshot)
        dirs={str(parent)+"/" for leaf in self.payload for parent in Path("/"+leaf).parents if parent!=Path("/")}
        owners=b"".join((O.PACKAGE+" /trial-work/target"+name+"\n").encode() for name in sorted(dirs|{"/"+n for n in self.payload}))
        outputs=dict(zip(("llhttp-before","llhttp-installed","llhttp-removed"),(self.base,self.after,self.base),strict=True))
        outputs.update({"llhttp-verify":b"untrusted" if wrong_signer else self.signed,"llhttp-owner":owners,
                        "llhttp-loader-before":T.encoded(G.probe_receipt(dig,present=False)),
                        "llhttp-loader-installed":T.encoded(G.probe_receipt(dig,present=True)),
                        "llhttp-loader-removed":T.encoded(G.probe_receipt(dig,present=False))})

        def command(role,argv,_,contents):
            calls.append(role)
            self.assertEqual(argv,G.commands(NONCE,dig)[role])
            if role=="llhttp-trust":
                self.assertEqual(contents,(self.fpr+":6:\n").encode())
            return outputs.get(role,b"")

        self.calls=calls
        with patch.object(G,"SUPPLEMENT",stage),patch.object(G,"payload_state") as states:
            result=G.exercise(trial,O,packet,self.base,sandbox,NONCE,{"GNUPGHOME":str(self.root/"trust")},command)
        self.assertEqual([item.args[-1] for item in states.call_args_list],[False,True,False])
        return result,outputs,packet

    def test_signed_guest_enforces_real_probe_order_and_raw_readback(self):
        result,outputs,packet=self.run_lifecycle()
        rows=[dict(role=role,argv=argv,exit=0,stdout=b64encode(outputs.get(role,b"")).decode(),stderr="")
              for role,argv in G.commands(NONCE,self.payload[O.REAL]["pin"]["sha256"]).items()]
        self.assertEqual(self.calls,list(G.ROLES))
        self.assertEqual(result["baseline_db"],result["restored_db"])
        check=lambda: G.readback(T.encoded(dict(result=result,commands=rows)),nonce=NONCE,base=self.base,
                                 supplement=packet,held=False,pin=T.pin,need=T.need,policy=O)
        self.assertEqual(check(),result)
        item=next(row for row in rows if row["role"]=="llhttp-loader-installed")
        item["stdout"]=b64encode(T.encoded(dict(result="static ELF only"))).decode()
        with self.assertRaisesRegex(ValueError,"shared library evidence"):
            check()

    def test_guest_refuses_wrong_signature_before_trust_or_install(self):
        with self.assertRaisesRegex(ValueError,"current selected TEST signature"):
            self.run_lifecycle(wrong_signer=True)
        self.assertNotIn("llhttp-trust",self.calls)
        self.assertNotIn("llhttp-install",self.calls)

    def test_guest_refuses_metadata_drift_with_exact_restored_inventory(self):
        with self.assertRaisesRegex(ValueError,"ALPM ownership or metadata"):
            self.run_lifecycle(db_drift=True)
        self.assertIn("llhttp-removed",self.calls)
        self.assertNotIn("llhttp-loader-removed",self.calls)


class Probe(unittest.TestCase):
    def test_native_call_contract_without_loading_a_host_object(self):
        lib=SimpleNamespace(llhttp_settings_init=Mock(),llhttp_init=Mock(),llhttp_execute=Mock(side_effect=[0,0,1,0]),
                            llhttp_finish=Mock(side_effect=[0,2]),llhttp_get_method=Mock(return_value=3),
                            llhttp_method_name=Mock(return_value=b"POST"),
                            llhttp_errno_name=Mock(side_effect=lambda code: [b"HPE_OK",b"HPE_INVALID_CONTENT_LENGTH",
                                                                            b"HPE_INVALID_EOF_STATE"][code]))
        observed=P.parse(lib)
        self.assertEqual(observed["split_request"],["HPE_OK"]*3)
        self.assertEqual(observed["invalid_length"],["HPE_INVALID_CONTENT_LENGTH"])
        self.assertEqual(observed["incomplete_body"],["HPE_OK","HPE_INVALID_EOF_STATE"])
        self.assertEqual(lib.llhttp_init.call_count,3)
        self.assertEqual(lib.llhttp_finish.call_count,2)
        self.assertEqual(lib.llhttp_execute.call_args_list[1].args[1:],(b"llo",3))


if __name__=="__main__":
    sys.addaudithook(deny)
    unittest.main(verbosity=2)
