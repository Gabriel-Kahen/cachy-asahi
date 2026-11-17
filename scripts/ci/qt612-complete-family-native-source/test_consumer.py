# SPDX-License-Identifier: MIT
"""Passive source and labelled consumer evidence MODEL controls."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("family_consumer_tests", HERE/"consumer.py")
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)
C, P, W = D.C, D.P, D.W


class Consumer(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="qt612-consumer-MODEL-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.out = self.root/"out"
        self.out.mkdir()
        self.lock = C.load_lock()
        self.checks = self.lock["consumer"]["checks"]
        self.inventory = self.root/"inventory"
        self.inventory.write_bytes(b"MODEL inventory byte evidence\n")
        self.plan = dict(image="sha256:"+"1"*64, consumer_commit=self.lock["consumer"]["commit"],
                         inventory_pin=C.pin(self.inventory.read_bytes()))

    def write(self, name, raw):
        (self.out/name).write_bytes(raw)

    def report(self):
        tests = []
        suite = ET.Element("testsuite", tests=str(len(self.checks)), failures="0", skipped="0", disabled="0")
        by_check = {}
        core = "/usr/lib/libQt6Core.so.6"
        for index, (name, marker) in enumerate(self.checks.items(), 11):
            tests.append(dict(name=name, command=[W.BUILD+"/"+name], properties=[dict(name="TIMEOUT",value=10)]))
            case = ET.SubElement(suite,"testcase",name=name,status="run")
            ET.SubElement(case,"system-out").text = marker+"\n"
            paths = set(W.RENDER) if name.endswith("render") else {core}
            if name.endswith("protocol"):
                paths |= {"/usr/lib/libwayland-client.so.0","/usr/lib/libwayland-server.so.0"}
            by_check[name] = sorted(paths)
            lines = [f"{index}: initialize program: {W.BUILD}/{name}"]
            lines += [f"{index}: calling init: {path}" for path in paths]
            self.write("loader."+str(index), ("\n".join(lines)+"\n").encode())
        self.write("test-list.log", C.encoded(dict(tests=tests)))
        self.write("ctest.xml", ET.tostring(suite))
        for phase in ("before","after"):
            self.write("inventory-"+phase+".log",self.inventory.read_bytes())
        self.write("configure.log",b"MODEL configure\n")
        self.write("build.log",("\n".join(sorted(W.TOOLS))+"\n").encode())
        self.write("tests.log",b"MODEL CTest console\n")
        commands = [("inventory-before",["/usr/bin/pacman","-Q"])]
        commands += [(role,argv) for role,argv,_ in W.commands(self.checks)]
        commands += [("inventory-after",["/usr/bin/pacman","-Q"])]
        names = {k:v["package"] for k,v in self.lock["components"].items()}
        owners = {}
        for path in sorted(W.TOOLS | {p for group in by_check.values() for p in group}):
            owner = names["gui_server"]
            resolved = path
            if W.LIB.fullmatch(path):
                soname = Path(path).name
                owner = next(row["package"] for row in self.lock["components"].values() if soname in row["metadata"]["provides"])
                resolved = path+".12.0"
            elif path.endswith("/libqsvg.so"):
                owner = names["svg"]
            elif path.endswith("/qsb"):
                owner = names["shadertools"]
            elif W.WAYLAND.fullmatch(path) or path.endswith("/wayland-scanner"):
                owner = "wayland"
            owners[path] = dict(resolved=resolved,package=owner,body=C.pin(b"MODEL inert installed bytes"))
        self.write("worker.json", C.encoded(dict(commands=[dict(role=role,argv=argv,exit=0) for role,argv in commands],owners=owners)))

    def read(self):
        return D.read_result(self.out,self.plan,inventory=self.inventory)

    def test_all_results_join_by_test_identity(self):
        self.report()
        result = self.read()
        self.assertEqual(result["checks"],sorted(self.checks))
        self.assertIsNone(result["native_acceptance"])
        self.assertEqual(set(result["loaded"]),set(self.checks))

    def test_missing_duplicate_skipped_and_crossed_markers_refuse(self):
        self.report()
        original = (self.out/"ctest.xml").read_bytes()
        marker = next(iter(self.checks.values())).encode()
        for replaced in (b"WRONG", marker+b"\n"+marker):
            self.write("ctest.xml", original.replace(marker,replaced))
            with self.assertRaises(ValueError):
                self.read()
        self.write("ctest.xml",original.replace(b'<system-out>',b'<skipped/><system-out>',1))
        with self.assertRaises(ValueError):
            self.read()

    def test_foreign_successful_load_refuses(self):
        self.report()
        logfile = next(self.out.glob("loader.*"))
        logfile.write_bytes(logfile.read_bytes()+b"99: calling init: /tmp/foreign/libQt6Core.so.6\n")
        with self.assertRaisesRegex(ValueError,"foreign Qt"):
            self.read()

    def test_wrong_installed_provider_or_inventory_refuses(self):
        self.report()
        data = json.loads((self.out/"worker.json").read_bytes())
        data["owners"]["/usr/lib/qt6/bin/qsb"]["package"] = self.lock["components"]["gui_server"]["package"]
        self.write("worker.json",C.encoded(data))
        with self.assertRaisesRegex(ValueError,"ownership"):
            self.read()
        self.report()
        self.write("inventory-after.log",b"MODEL changed\n")
        with self.assertRaisesRegex(ValueError,"Different installed inventory"):
            self.read()

    def test_full_inventory_and_held_dependencies(self):
        root = self.root/"source"
        root.mkdir()
        raw = "".join(f"model-{i:03d} 1-1\n" for i in range(356)).encode()
        (root/"expected356.lock").write_bytes(raw)
        lock = self.lock["consumer"]
        files = {"expected356.lock": C.pin(raw)}
        files.update({"consumer/"+n:dict(pin,mode=0o644) for n,pin in lock["files"].items()})
        mapping = dict(input_plan_complete=True,desktop_consumer=lock["commit"],files=files)
        self.inventory.write_bytes(P.expected_inventory(root,mapping,P.DESKTOP_CONSUMER))
        self.assertEqual(len(self.inventory.read_bytes().splitlines()),361)
        with patch.object(D.C,"read_source",return_value=mapping):
            options = dict(source=root,source_map_sha256="0"*64,image=self.plan["image"],
                           inventory=self.inventory,output=self.root/"fresh",nonce="2"*32)
            plan = D.commands(**options)
            self.assertIn("--read-only",plan["argv"])
            self.assertEqual(plan["argv"][plan["argv"].index("--network")+1],"none")
            mapping["input_plan_complete"] = False
            with self.assertRaisesRegex(ValueError,"Held signed dependency"):
                D.commands(**options)


if __name__ == "__main__":
    unittest.main()
