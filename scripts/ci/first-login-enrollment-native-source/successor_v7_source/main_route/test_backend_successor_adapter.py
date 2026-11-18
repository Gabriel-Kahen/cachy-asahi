# SPDX-License-Identifier: MIT
"""Offline controls for producer custody and the exact successor pair hook."""
import argparse
import ast
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import backend_successor_adapter as A
import emit_backend_pair_hook as E
import test_backend_handoff as base
from test_backend_handoff import BINDING, NONCE, capsule_fixture

B, C, H, R = A.H.review, A.C, A.H, A.R


def model_pairs(profile, delegation):
    raw = capsule_fixture()
    manifest = C.decode(raw["manifest"])
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw["capsule"])),mode="r:") as tar:
        files = {item.name.split("/",1)[1]:tar.extractfile(item).read() for item in tar}
    files["delegation.json"] = delegation
    manifest["delegation_pin"] = C.pin(delegation)
    pairs={}
    for kind in A.KINDS:
        recipe=profile["packages"][kind]
        package=(kind+" FENCED PACKAGE").encode()
        pair=dict(binding=BINDING,nonce=NONCE,archives=[C.pin(package)]*2,matching_pair=True,
                  component=dict(name=recipe["name"],version=recipe["version"],architecture="any"),**C.FINAL)
        pair_name=kind+"-pair.public.json"
        files[pair_name]=C.encoded(pair)
        pairs[kind]=C.encoded(pair|{"comparison_receipt":dict(step="current-"+kind+"-compare",exit=0,success=True)})
        manifest["origins"][pair_name]=dict(pin=C.pin(pairs[kind]),projection=True)
        for label in ("a","b"):
            files[f"builds/{kind}-{label}/artifacts/{recipe['archive']}"]=package
    manifest["files"]={name:C.pin(body) for name,body in files.items() if name!="retention-manifest.json"}
    files["retention-manifest.json"]=raw["manifest"]=C.encoded(manifest)
    sink=io.BytesIO()
    with tarfile.open(fileobj=sink,mode="w",format=tarfile.GNU_FORMAT) as tar:
        for name,body in files.items():
            item=tarfile.TarInfo("delegated-backend-public-v4/"+name)
            item.mode,item.size=0o444,len(body)
            tar.addfile(item,io.BytesIO(body))
    raw["capsule"]=gzip.compress(sink.getvalue(),mtime=0)
    owner=C.decode(raw["owner"]);executor=C.decode(raw["executor"])
    owner["result"]["retention"].update(capsule_pin=C.pin(raw["capsule"]),manifest_pin=C.pin(raw["manifest"]))
    executor.update(owner=owner,delegation_pin=manifest["delegation_pin"])
    raw.update(owner=C.encoded(owner),executor=C.encoded(executor))
    return raw,pairs,files,manifest


class Boundary(unittest.TestCase):
    def test_selection_default_and_exact_support_partition(self):
        self.assertEqual(A.producer(object())["status"],"SOURCE207_PUBLIC_CONTROL_ONLY")
        self.assertEqual(len(A.PRODUCER_ROLES),13)
        self.assertEqual(len(A.INDEPENDENT_ROLES),9)
        self.assertEqual(A.PRODUCER_ROLES|A.INDEPENDENT_ROLES,H.SUPPORT)
        self.assertFalse(A.PRODUCER_ROLES&A.INDEPENDENT_ROLES)

    def test_byte_pair_requires_actual_original_and_both_archives(self):
        recipes={kind:dict(name=kind,version="1",archive=kind+".pkg.tar.zst") for kind in A.KINDS}
        _,pairs,files,manifest=model_pairs({"packages":recipes},C.encoded({"model":True}))
        kind="first-login"
        self.assertEqual(A.package_pair(files,manifest,kind,recipes[kind],pairs[kind])[1],
                         [b"first-login FENCED PACKAGE"]*2)
        with self.assertRaisesRegex(ValueError,"HOLD_SOURCE207_ORIGINAL_PAIR_PIN"):
            A.package_pair(files,manifest,kind,recipes[kind],files[kind+"-pair.public.json"])
        files["builds/first-login-b/artifacts/first-login.pkg.tar.zst"]=b"substituted"
        with self.assertRaisesRegex(ValueError,"HOLD_SOURCE207_PAIR_ARCHIVE_BODIES"):
            A.package_pair(files,manifest,kind,recipes[kind],pairs[kind])

    def test_staged_directory_matches_real_assembler_selected_product_api(self):
        path=Path(__file__).resolve().parents[2]/"payload/native/test_inputs_current_v3.py"
        spec=importlib.util.spec_from_file_location("source207_product_assembler_fixture",path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fixture=module.Controls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        row=fixture.selected_product()
        bodies={role:Path(ref["path"]).read_bytes() for role,ref in row.items()
                if role not in ("kind","selection_role","archives","signatures")}
        for group in ("archives","signatures"):
            bodies.update({f"{group}-{i}":Path(ref["path"]).read_bytes() for i,ref in enumerate(row[group])})
        stage=Path(self.enterContext(TemporaryDirectory()))
        archive="cachy-asahi-first-login-0.1.0-3-any.pkg.tar.zst"
        def check(ref):
            return module.A.selected_product("first-login",ref,fixture.profile,fixture.d,fixture.H,
                                              fixture.request["test_trust"])
        emitted=A.retain_product(stage/"first-login",archive,row["selection_role"],bodies,check)
        self.assertEqual(check(emitted)["pair_adoption"],emitted)
        self.assertEqual([Path(ref["path"]).name for ref in emitted["archives"]],[archive]*2)
        self.assertEqual(Path(emitted["pair"]["path"]).read_bytes(),bodies["pair"])
        broken=bodies|{"root_test":bodies["root_test"]+b" "}
        with self.assertRaises(ValueError):
            A.retain_product(stage/"broken",archive,row["selection_role"],broken,check)
        self.assertEqual([path.name for path in stage.iterdir()],["first-login"])


def genuine_controls(source,launcher):
    class Genuine(unittest.TestCase):
        def test_exact_two_leaf_emitter_and_privileged_copy_boundaries(self):
            launch=Tread(launcher)
            result=E.proposed(source,launch)
            self.assertEqual(set(result),{E.EXECUTOR,C.LAUNCHER})
            with self.assertRaisesRegex(ValueError,"HOLD_SOURCE207_HOOK_PREDECESSOR"):
                E.proposed(source,launch+b"\n")
            self.assertEqual(result,E.proposed(source,launch))
            syntax=ast.parse(result[E.EXECUTOR])
            controller=next(node for node in syntax.body if isinstance(node,ast.ClassDef) and node.name=="Controller")
            method=next(node for node in controller.body if isinstance(node,ast.FunctionDef) and node.name=="retain_backend_pairs")
            retain=next(node for node in controller.body if isinstance(node,ast.FunctionDef) and node.name=="retain")
            body=ast.unparse(retain)
            self.assertIn("if retain_backend_pairs:",body)
            self.assertIn("self.retain_backend_pairs(target)",body)
            self.assertIn("self.out.mkdir(mode=457)",ast.unparse(controller))
            self.assertIn("os.chown(path, self.uid, self.gid)",body)
            privileged_custody=[]
            def record_chown(path,uid,gid):
                privileged_custody.append((path,uid,gid))
            mock_os=SimpleNamespace(**{name:getattr(os,name) for name in ("open","fdopen","O_WRONLY","O_CREAT","O_EXCL","O_NOFOLLOW")},
                                    fchown=record_chown,chown=record_chown)
            scope=dict(os=mock_os,json=json,pin=C.pin,need=C.need,
                       read_data=lambda path,cap=2*H.T.MIB:H.T.read_local(str(path),cap))
            exec(compile(ast.Module(body=[method],type_ignores=[]),"ACTOR_FENCED_COPY_METHOD","exec"),scope)
            with TemporaryDirectory() as temporary:
                root=Path(temporary)
                nested=root/"volume/work/stage/stage"
                nested.mkdir(parents=True)
                target=root/"evidence"
                manifest=target/"public/delegated-backend-public-v4/retention-manifest.json"
                manifest.parent.mkdir(parents=True)
                profile=C.decode((source/A.PROFILE_MEMBER).read_bytes())
                _,pairs,_,held=model_pairs(profile,C.encoded({"model":True}))
                for kind,raw in pairs.items():
                    (nested/(kind+"-pair.json")).write_bytes(raw)
                manifest.write_bytes(C.encoded(held))
                mock_owner=SimpleNamespace(c=dict(stage="backend",binding=BINDING),nonce=NONCE,out=root,uid=1001,gid=1001)
                scope["retain_backend_pairs"](mock_owner,target)
                actual=root/A.PAIRS
                self.assertEqual({file.name:file.read_bytes() for file in actual.iterdir()},
                                 {kind+".json":raw for kind,raw in pairs.items()})
                self.assertEqual(len(privileged_custody),3)
                self.assertTrue(all((uid,gid)==(1001,1001) for _,uid,gid in privileged_custody))
                self.assertTrue(all(file.stat().st_mode&0o777==0o600 for file in actual.iterdir()))

        def test_complete_producer_capture_on_exact_source_and_consumer_hold(self):
            fixture=base.PrivateHandoff()
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
            profile=C.decode((source/A.PROFILE_MEMBER).read_bytes())
            delegation=C.encoded(dict(binding={key:BINDING[key] for key in ("source","ref","source_lock")},
                                      stage="backend",nonce=NONCE))
            data,pairs,_,_=model_pairs(profile,delegation)
            for role,raw in data.items():
                (fixture.owner/H.CONTENTS[role][0]).write_bytes(raw)
                fixture.selection["expected"][role]=C.pin(raw)
            path=fixture.owner/A.PAIRS
            path.mkdir()
            for kind,raw in pairs.items():
                (path/(kind+".json")).write_bytes(raw)
            grant,assembly=(C.encoded(dict(model=role)) for role in A.EMBEDDED)
            request=dict(delegation_json=delegation.decode(),delegation_pin=C.pin(delegation),
                         material_staging=dict(grant_json=grant.decode(),grant_pin=C.pin(grant),
                                               assembler_request=dict(json=assembly.decode(),pin=C.pin(assembly))))
            request_raw=C.encoded(request)
            for role,(member,_) in A.DIRECT.items():
                path=fixture.control/member
                path.parent.mkdir(exist_ok=True)
                if role!="prerequisite_launcher":
                    path.write_bytes(C.encoded(dict(model=role)))
            (fixture.control/"private/request.json").write_bytes(request_raw)
            launch=C.decode(fixture.launcher.read_bytes())|{"request_pin":C.pin(request_raw)}
            fixture.launcher.write_bytes(C.encoded(launch))
            fixture.selection["expected"]["launcher"]=C.pin(C.encoded(launch))
            selected=dict(schema=1,kind=A.SELECTION,issuer="Root",approved=True,snapshot=fixture.selection,
                          source_root=str(source),request_pin=C.pin(request_raw))
            result=A.producer(selected,mode=H.MODE)
            output=Path(result["path"])
            self.assertEqual(set(result["support"]),A.PRODUCER_ROLES)
            self.assertEqual({name.name for name in output.iterdir()},{"pairs","producer.json","snapshot","support"})
            self.assertEqual((output/"support/material_close.json").read_bytes(),
                             (fixture.control/"material-domain-close.json").read_bytes())
            self.assertEqual((output/"support/material_assembly_request.json").read_bytes(),assembly)
            self.assertEqual((output/"pairs/first-login.json").read_bytes(),pairs["first-login"])
            self.assertEqual({path.name for path in fixture.public.iterdir()},
                             {"launcher-report.json","context.json","timing.json","controller-observation.json",
                              "material-staging.json","host-prerequisite.json"})
            result=A.consumer(output,result["producer_pin"],expected_raw=b"",expected_pin={},
                              source_files={},independently_retained={},now=1000)
            self.assertEqual(result["status"],"HOLD_SOURCE207_INDEPENDENT_BACKEND_SUPPORT")
            self.assertEqual(set(result["missing"]),A.INDEPENDENT_ROLES)
    return Genuine


def Tread(path):
    return H.T.read_local(str(path),A.S.CORE["bytes"])


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path)
    parser.add_argument("--launcher",type=Path)
    args,remaining=parser.parse_known_args()
    sys.addaudithook(B.fence)
    if args.source and args.launcher:
        Genuine=genuine_controls(args.source,args.launcher)
    elif args.source or args.launcher:
        parser.error("supply the exact held Source checkout and launcher together")
    unittest.main(argv=[sys.argv[0],*remaining])
