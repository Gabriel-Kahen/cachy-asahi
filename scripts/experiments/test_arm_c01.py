"""Temp/mocked controller tests plus an own-driver/system-zlib C fixture.

The C fixture is host-only API validation, never an upstream or native ARM build.
"""
import copy
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("corpus", HERE / "corpus.py")
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)
SPEC = importlib.util.spec_from_file_location("arm_c01_under_test", HERE / "arm_c01.py")
a = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"corpus": corpus}):
    SPEC.loader.exec_module(a)

ELF_GOOD = (b"Class: ELF64\nMachine: AArch64\n"
            b" LOAD 0x000000 0x0000000000000000 0x0000000000000000 0x000100 0x000100 R E 0x10000\n"
            b" [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]\n"
            b" 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n")


def config_bytes(variant, extra=" -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN"):
    cflags, ldflags = a.build_flags(variant)
    return f"CC=gcc\nAR=gcc-ar\nRANLIB=gcc-ranlib\nCFLAGS={cflags} -fPIC{extra}\nLDFLAGS={ldflags}\n".encode()


def valid_guard():
    table = {"/": {"fs": "overlay", "options": ["ro"], "root": "/"},
             "/inputs": {"fs": "ext4", "options": ["ro"]},
             "/out": {"fs": "ext4", "options": ["rw"]},
             "/tmp": {"fs": "tmpfs", "options": ["rw", "nosuid", "nodev"], "root": "/"}}
    table.update({point: {"fs": fs, "root": "/", "options": ["ro" if point.startswith("/sys") else "rw"] +
                  (["nosuid"] if point == "/dev" else ["nosuid", "noexec"] if point == "/dev/pts" else ["nosuid", "nodev", "noexec"])}
                  for point, fs in a.KERNEL.items()})
    return {"arch": "aarch64", "uid": 1000, "gid": 1000, "docker": True, "interfaces": ["lo"],
            "caps": dict.fromkeys(a.CAPS, 0), "nnp": 1, "sockets": [], "devices": [],
            "runtime_files": {}, "null_masks": {}, "directory_masks": {},
            "owners": {p: {"uid": 1000, "gid": 1000, "mode": 0o700, "safe": True}
                       for p in ("/tmp", "/out")},
            "mounts": table, "home": "/tmp/home", "nonce": "a" * 32}


class IsolatedTests(unittest.TestCase):
    def enterContext(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cachy-asahi-c01-tests-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.enterContext(patch.dict(a.os.environ, {key: value for key, value in a.os.environ.items()
                                                  if not key.startswith("DOCKER_")}, clear=True))
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            self.enterContext(patch.object(a.os, name, return_value=1000))
        # Tripwires apply to all tests unless explicitly replaced by a mock.
        for target in ("Popen", "run", "call", "check_call", "check_output"):
            self.enterContext(patch.object(a.subprocess, target, side_effect=AssertionError(
                "No real Docker, pacman, GPG, upstream build or subprocess allowed")))
        self.enterContext(patch.object(a.os, "killpg", side_effect=AssertionError("No real process-group signal")))
        self.enterContext(patch.object(a.signal, "signal", return_value=signal.SIG_DFL))
        self.enterContext(patch.object(a.signal, "pthread_sigmask", return_value=set()))
        self.enterContext(patch.object(a.time, "sleep", side_effect=AssertionError("No blocking test sleeps")))


class StrictDriverHostFixtureTests(unittest.TestCase):
    """Compile only our private driver; inject actual C API error return values."""

    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("own-driver host fixture requires installed GCC and system zlib")
        temp = tempfile.TemporaryDirectory(prefix="cachy-asahi-own-driver-fixture-")
        cls.addClassCleanup(temp.cleanup)
        cls.root = Path(temp.name)
        source, wrapper = cls.root / "strict.c", cls.root / "fault.c"
        cls.binary = cls.root / "strict-gzip"
        source.write_bytes(a.STRICT_DRIVER)
        wrapper.write_text('''#include <stdlib.h>
#include <zlib.h>
int __real_inflate(z_streamp, int);
int __real_inflateInit2_(z_streamp, int, const char *, int);
int __real_inflateEnd(z_streamp);
int __wrap_inflate(z_streamp stream, int flush) {
    const char *fault = getenv("STRICT_INFLATE_FAULT");
    return fault ? (int)strtol(fault, 0, 10) : __real_inflate(stream, flush);
}
int __wrap_inflateInit2_(z_streamp stream, int bits, const char *version, int size) {
    const char *fault = getenv("STRICT_INIT_FAULT");
    return fault ? (int)strtol(fault, 0, 10) : __real_inflateInit2_(stream, bits, version, size);
}
int __wrap_inflateEnd(z_streamp stream) {
    const char *fault = getenv("STRICT_END_FAULT");
    int result = __real_inflateEnd(stream);
    return fault ? (int)strtol(fault, 0, 10) : result;
}
''')
        built = subprocess.run([compiler, "-O2", "-Wall", "-Wextra", "-Werror",
                                str(source), str(wrapper), "-Wl,--wrap=inflate",
                                "-Wl,--wrap=inflateInit2_", "-Wl,--wrap=inflateEnd",
                                "-lz", "-o", str(cls.binary)], capture_output=True, timeout=20)
        if built.returncode:
            raise AssertionError("own-driver host fixture compile failed: " + built.stderr.decode(errors="replace"))
        corpus.create(cls.root / "corpus", b"public fixture source")

    def run_driver(self, name="gzip-reference.gz", fault=None):
        env = {key: value for key, value in os.environ.items() if not key.startswith("STRICT_")}
        if fault:
            env[fault[0]] = str(fault[1])
        return subprocess.run([str(self.binary)], input=(self.root / "corpus" / name).read_bytes(),
                              capture_output=True, env=env, timeout=5)

    def test_valid_crc_and_truncation_actual_system_api(self):
        valid = self.run_driver()
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(valid.stdout, corpus.GZIP_PAYLOAD)
        for name in ("corrupt-crc.gz", "truncated-trailer.gz"):
            rejected = self.run_driver(name)
            with self.subTest(input=name):
                self.assertEqual(rejected.returncode, 2, rejected.stderr)

    def test_inflate_resource_internal_and_unknown_errors_are_not_rejections(self):
        # GCC linker wrapping reproduces actual C return-code handling on valid gzip.
        # Z_MEM_ERROR, Z_STREAM_ERROR, Z_VERSION_ERROR, Z_NEED_DICT and unknown.
        for code in (-4, -2, -6, 2, -99):
            result = self.run_driver(fault=("STRICT_INFLATE_FAULT", code))
            with self.subTest(code=code):
                self.assertEqual(result.returncode, 3, result.stderr)
        for code in (-3, -5):  # Only Z_DATA_ERROR and Z_BUF_ERROR earn exit 2.
            result = self.run_driver(fault=("STRICT_INFLATE_FAULT", code))
            with self.subTest(code=code):
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_initialization_and_cleanup_failures_are_not_rejections(self):
        for operation in ("STRICT_INIT_FAULT", "STRICT_END_FAULT"):
            for code in (-6, -4, -2, -99):
                result = self.run_driver(fault=(operation, code))
                with self.subTest(operation=operation, code=code):
                    self.assertEqual(result.returncode, 3, result.stderr)


class GuardTests(IsolatedTests):
    def test_valid_native_nonroot_private_contract(self):
        for arch in ("aarch64", "arm64"):
            record = valid_guard(); record["arch"] = arch
            self.assertIsNone(a.guard(record, "a" * 32))
        record = valid_guard()
        record["mounts"]["/etc/hosts"] = {"fs": "ext4", "options": ["rw"]}
        record["runtime_files"]["/etc/hosts"] = True
        self.assertIsNone(a.guard(record, "a" * 32))

    def test_native_privilege_network_nonce_home_and_socket_failures(self):
        bad = [("arch", "x86_64"), ("uid", 0), ("docker", False),
               ("interfaces", ["eth0", "lo"]), ("nnp", 0),
               ("nonce", "b" * 32), ("home", "/home/caller"),
               ("sockets", ["/run/docker.sock"]), ("sockets", ["/inputs/alternate-control.sock"]),
               ("devices", ["/dev/host-disk"])]
        for key, value in bad:
            record = valid_guard(); record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.guard(record, "a" * 32)
        for capability in a.CAPS:
            record = valid_guard(); record["caps"][capability] = 1
            with self.subTest(capability=capability), self.assertRaises(ValueError):
                a.guard(record, "a" * 32)
        record = valid_guard(); del record["caps"]["CapAmb"]
        with self.assertRaises(ValueError):
            a.guard(record, "a" * 32)

    def test_metadata_directory_and_nonsemantic_null_masks_refused(self):
        record = valid_guard()
        record["mounts"]["/etc/hosts"] = {"fs": "ext4", "options": ["rw"]}
        record["runtime_files"]["/etc/hosts"] = False
        with self.assertRaisesRegex(ValueError, "metadata"):
            a.guard(record, "a" * 32)
        for point in a.NULL_MASKS:
            record = valid_guard()
            record["mounts"][point] = {"fs": "tmpfs", "options": ["rw", "nosuid"], "root": "/null"}
            record["null_masks"][point] = True
            self.assertIsNone(a.guard(record, "a" * 32))
            record["null_masks"][point] = False
            with self.subTest(mask=point), self.assertRaisesRegex(ValueError, "masked"):
                a.guard(record, "a" * 32)

    def test_tmp_and_output_require_safe_private_owned_directories(self):
        for point in ("/tmp", "/out"):
            for key, value in (("uid", 0), ("gid", 0), ("mode", 0o777), ("safe", False)):
                record = valid_guard(); record["owners"][point][key] = value
                with self.subTest(point=point, key=key), self.assertRaisesRegex(ValueError, "owned"):
                    a.guard(record, "a" * 32)

    def test_extra_or_substituted_mounts_and_nonprivate_tmp_refused(self):
        for point in ("/home", "/dev/host-disk", "/run/docker.sock"):
            record = valid_guard()
            record["mounts"][point] = {"fs": "ext4", "options": ["rw"]}
            with self.subTest(point=point), self.assertRaises(ValueError):
                a.guard(record, "a" * 32)
        for point in ("/sys", "/dev"):
            record = valid_guard(); record["mounts"][point]["fs"] = "ext4"
            with self.subTest(substituted=point), self.assertRaises(ValueError):
                a.guard(record, "a" * 32)
        for point, options in (("/", ["rw"]), ("/inputs", ["rw"]), ("/out", ["ro"]),
                               ("/tmp", ["rw", "nodev"]), ("/tmp", ["rw", "nosuid"]),
                               ("/sys", ["rw"])):
            record = valid_guard(); record["mounts"][point]["options"] = options
            with self.subTest(point=point, options=options), self.assertRaises(ValueError):
                a.guard(record, "a" * 32)
        record = valid_guard(); record["mounts"]["/tmp"]["fs"] = "ext4"
        with self.assertRaises(ValueError):
            a.guard(record, "a" * 32)

    def test_wrong_data_filesystems_ambiguous_access_and_runtime_subtrees_refused(self):
        for point in ("/inputs", "/out"):
            for filesystem in ("proc", "sysfs", "devpts", "mqueue"):
                record = valid_guard(); record["mounts"][point]["fs"] = filesystem
                with self.subTest(point=point, fs=filesystem), self.assertRaisesRegex(ValueError, "data filesystem"):
                    a.guard(record, "a" * 32)
        for point in valid_guard()["mounts"]:
            record = valid_guard(); record["mounts"][point]["options"] += ["ro", "rw"]
            with self.subTest(point=point), self.assertRaisesRegex(ValueError, "ambiguous"):
                a.guard(record, "a" * 32)
        for point in ("/", "/tmp", *a.KERNEL):
            record = valid_guard(); record["mounts"][point]["root"] = "/host-subtree"
            with self.subTest(point=point), self.assertRaisesRegex(ValueError, "subtree"):
                a.guard(record, "a" * 32)
        for point in a.KERNEL:
            required = {"nosuid"} if point == "/dev" else {"nosuid", "noexec"} if point == "/dev/pts" else {"nosuid", "nodev", "noexec"}
            for flag in required:
                record = valid_guard(); record["mounts"][point]["options"].remove(flag)
                with self.subTest(point=point, flag=flag), self.assertRaisesRegex(ValueError, "flags"):
                    a.guard(record, "a" * 32)

    def test_standard_docker_mask_roles_sources_and_null_access(self):
        record = valid_guard()
        for point in a.PROC_MASKS:
            record["mounts"][point] = {"fs": "proc", "options": ["ro", "nosuid", "nodev", "noexec"], "root": point.removeprefix("/proc")}
        for point in a.MASKS - a.PROC_MASKS - a.NULL_MASKS:
            record["mounts"][point] = {"fs": "tmpfs", "options": ["ro"], "root": "/"}
            record["directory_masks"][point] = True
        for access in ("ro", "rw"):
            for point in a.NULL_MASKS:
                record["mounts"][point] = {"fs": "tmpfs", "options": [access, "nosuid"], "root": "/null"}
                record["null_masks"][point] = True
            a.guard(record, "a" * 32)
        for point in a.MASKS:
            changed = copy.deepcopy(record); changed["mounts"][point]["root"] = "/unreviewed"
            with self.subTest(point=point), self.assertRaises(ValueError):
                a.guard(changed, "a" * 32)
        changed = copy.deepcopy(record); changed["directory_masks"]["/sys/firmware"] = False
        with self.assertRaisesRegex(ValueError, "empty masked"):
            a.guard(changed, "a" * 32)

    def test_inventory_rejects_empty_duplicate_and_malformed_rows(self):
        self.assertEqual(a.inventory(b"gcc 1\nzlib 2\n"), {"gcc": "1", "zlib": "2"})
        for data in (b"", b"gcc 1\ngcc 2\n", b"gcc\n", b"gcc 1 extra\n", b"gcc 1\n\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                a.inventory(data)

    def test_mount_parser_decodes_names_and_rejects_duplicates(self):
        line = "1 2 0:1 / /space\\040name ro - tmpfs tmpfs ro\n"
        self.assertEqual(a.mounts(line)["/space name"], {"fs": "tmpfs", "options": ["ro"], "root": "/"})
        with self.assertRaises(ValueError):
            a.mounts(line + line)


class SourceTests(IsolatedTests):
    def test_elf_layout_aarch64_alignment_metadata_is_not_hardware_execution(self):
        result = a.elf_layout(ELF_GOOD)
        self.assertEqual(result["loads"][0]["alignment"], 65536)
        self.assertEqual(result["needed"], ["libc.so.6"])
        self.assertEqual(result["interpreter"], ["/lib/ld-linux-aarch64.so.1"])
        self.assertEqual(result["16k_execution"], "NOT RUN")

    def test_elf_layout_rejects_4k_mismatch_x86_wx_and_missing_loads(self):
        cases = [ELF_GOOD.replace(b"0x10000", b"0x1000"),
                 ELF_GOOD.replace(b"0x0000000000000000", b"0x0000000000001000", 1),
                 ELF_GOOD.replace(b"AArch64", b"Advanced Micro Devices X86-64"),
                 ELF_GOOD.replace(b"R E 0x10000", b"RWE 0x10000"),
                 b"Class: ELF64\nMachine: AArch64\n"]
        for index, data in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                a.elf_layout(data)

    def archive(self, rows):
        source = self.root / "source.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            for name, kind, payload in rows:
                entry = tarfile.TarInfo(name); entry.type = kind; entry.mode = 0o4777
                if kind == tarfile.REGTYPE:
                    entry.size = len(payload); archive.addfile(entry, io.BytesIO(payload))
                else:
                    entry.linkname = "outside"; archive.addfile(entry)
        return source

    def test_pinned_source_extracts_bytes_without_special_mode_bits(self):
        source = self.archive([("zlib-1.3.2/README", tarfile.REGTYPE, b"fixture"),
                               ("zlib-1.3.2/sub/", tarfile.DIRTYPE, b"")])
        output = self.root / "unpacked"; output.mkdir()
        with patch.object(a, "SOURCE_SHA", a.sha(source)):
            a.extract(source, output)
        self.assertEqual((output / "README").read_bytes(), b"fixture")
        self.assertEqual((output / "README").stat().st_mode & 0o7777, 0o755)

    def test_source_hash_refused_before_output_writes(self):
        source = self.archive([("zlib-1.3.2/README", tarfile.REGTYPE, b"fixture")])
        output = self.root / "unpacked"; output.mkdir()
        with patch.object(a, "SOURCE_SHA", "0" * 64), self.assertRaisesRegex(ValueError, "pinned"):
            a.extract(source, output)
        self.assertEqual(list(output.iterdir()), [])

    def test_traversal_wrong_root_absolute_link_and_device_members_refused(self):
        cases = [("zlib-1.3.2/../escape", tarfile.REGTYPE),
                 ("/zlib-1.3.2/escape", tarfile.REGTYPE), ("wrong/escape", tarfile.REGTYPE),
                 ("zlib-1.3.2/link", tarfile.SYMTYPE), ("zlib-1.3.2/hard", tarfile.LNKTYPE),
                 ("zlib-1.3.2/dev", tarfile.CHRTYPE), ("zlib-1.3.2/fifo", tarfile.FIFOTYPE)]
        for index, (name, kind) in enumerate(cases):
            source = self.archive([(name, kind, b"payload")])
            output = self.root / f"unpacked-{index}"; output.mkdir()
            with self.subTest(name=name), patch.object(a, "SOURCE_SHA", a.sha(source)), self.assertRaises(ValueError):
                a.extract(source, output)
            self.assertEqual(list(output.iterdir()), [])
        self.assertFalse((self.root / "escape").exists())

    def test_duplicate_and_member_count_bounds(self):
        for rows in ([('zlib-1.3.2/a', tarfile.REGTYPE, b'a')] * 2,
                     [(f'zlib-1.3.2/f{i}', tarfile.REGTYPE, b'') for i in range(2049)]):
            source = self.archive(rows)
            output = self.root / f"unpacked-{len(rows)}"; output.mkdir()
            with patch.object(a, "SOURCE_SHA", a.sha(source)), self.assertRaisesRegex(ValueError, "duplicate"):
                a.extract(source, output)
            self.assertLessEqual(len(list(output.iterdir())), 2048)

    def test_oversized_header_refused_without_allocating_large_payload(self):
        source = self.root / "small"; source.write_bytes(b"pinned fixture")
        member = tarfile.TarInfo("zlib-1.3.2/oversized"); member.size = 8 * 1024**2 + 1
        archive = Mock(); archive.__enter__ = Mock(return_value=[member]); archive.__exit__ = Mock(return_value=False)
        output = self.root / "out"; output.mkdir()
        with patch.object(a, "SOURCE_SHA", a.sha(source)), patch.object(a.tarfile, "open", return_value=archive), self.assertRaisesRegex(ValueError, "bound"):
            a.extract(source, output)
        self.assertEqual(list(output.iterdir()), [])

    def test_regular_refuses_symlinks_hardlinks_and_size_before_read(self):
        source = self.root / "regular"; source.write_bytes(b"fixture")
        link = self.root / "link"; link.symlink_to(source)
        with self.assertRaises(ValueError):
            a.regular(link)
        hard = self.root / "hard"; hard.hardlink_to(source)
        with self.assertRaises(ValueError):
            a.regular(source)
        hard.unlink()
        with self.assertRaises(ValueError):
            a.regular(source, 1)


class CommandTests(IsolatedTests):
    def group_gone(self, pid, sig):
        if sig == 0:
            raise ProcessLookupError()

    def test_timeout_records_failure_and_kills_mock_group(self):
        child = Mock(pid=987654)
        child.wait.side_effect = [subprocess.TimeoutExpired(["fixture"], 1), 0, 0, 0]
        with patch.object(a.subprocess, "Popen", return_value=child), patch.object(a.os, "killpg", side_effect=self.group_gone) as kill, patch.object(a.time, "monotonic", side_effect=[0, 0, 0, 2, 2, 3]):
            runner = a.Commands(self.root, seconds=10)
            with self.assertRaisesRegex(ValueError, "timeout"):
                runner.run("timeout", ["FIXTURE-never-real-command"], timeout=1)
        self.assertIn(unittest.mock.call(987654, signal.SIGTERM), kill.call_args_list)
        self.assertIn(unittest.mock.call(987654, signal.SIGKILL), kill.call_args_list)
        row = json.loads((self.root / "commands.json").read_text())[0]
        self.assertEqual((row["status"], row["cleanup"]), ("FAIL", "PASS"))

    def test_cancellation_still_cleans_attached_group_and_records_failure(self):
        child = Mock(pid=987654); child.wait.side_effect = [a.Cancelled(), 0, 0, 0]
        with patch.object(a.subprocess, "Popen", return_value=child), patch.object(a.os, "killpg", side_effect=self.group_gone):
            runner = a.Commands(self.root)
            with self.assertRaises(a.Cancelled):
                runner.run("cancelled", ["FIXTURE-never-real-command"])
        self.assertIsNone(runner.child)
        self.assertEqual(json.loads((self.root / "commands.json").read_text())[0]["status"], "FAIL")

    def test_failed_command_retains_bounded_real_log_bytes(self):
        child = Mock(pid=987654); child.wait.side_effect = [a.Cancelled(), 0, 0, 0]
        def spawn(argv, **kwargs):
            kwargs["stderr"].write(b"synthetic compiler diagnostic before cancellation\n")
            kwargs["stderr"].flush()
            return child
        with patch.object(a.subprocess, "Popen", side_effect=spawn), patch.object(a.os, "killpg", side_effect=self.group_gone):
            with self.assertRaises(a.Cancelled):
                a.Commands(self.root).run("failed-compiler", ["FIXTURE-never-real-command"])
        row = json.loads((self.root / "commands.json").read_text())[0]
        log = self.root / row["log"]
        self.assertEqual(row["log_sha256"], a.sha(log))
        self.assertEqual(row["log_bytes"], log.stat().st_size)
        self.assertIn(b"diagnostic before cancellation", log.read_bytes())
        self.assertEqual((row["status"], row["cleanup"]), ("FAIL", "PASS"))

    def test_original_sample_truncation_zero_exit_remains_failed_rejection(self):
        manifest = corpus.create(self.root / "corpus", b"public fixture")
        source = self.root / "corpus/truncated-trailer.gz"
        child = Mock(pid=987654); child.wait.return_value = 0
        def sample(argv, **kwargs):
            kwargs["stdout"].write(corpus.GZIP_PAYLOAD)
            return child
        with patch.object(a.subprocess, "Popen", side_effect=sample), patch.object(a.os, "killpg", side_effect=self.group_gone):
            with self.assertRaisesRegex(ValueError, "command exit differs"):
                a.Commands(self.root).run("historical-sample-truncation", ["FIXTURE-minigzip", "-d"],
                                          source=source, target=self.root / "sample-output.bin", allowed=tuple(range(1,256)))
        row = json.loads((self.root / "commands.json").read_text())[0]
        self.assertEqual((row["status"], row["exit_code"], row["failure_kind"]), ("FAIL", 0, "ValueError"))
        self.assertNotIn(0, row["allowed_exit_codes"])
        self.assertEqual(row["stdout"]["bytes"], len(corpus.GZIP_PAYLOAD))

    def test_success_still_checks_attached_descendant_group(self):
        child = Mock(pid=987654); child.wait.return_value = 0
        with patch.object(a.subprocess, "Popen", return_value=child), patch.object(a.os, "killpg", side_effect=self.group_gone) as kill:
            runner = a.Commands(self.root)
            self.assertEqual(runner.run("success", ["FIXTURE-never-real-command"]), b"")
        kill.assert_any_call(child.pid, signal.SIGKILL)
        kill.assert_any_call(child.pid, 0)

    def test_spawn_restores_child_cancellation_mask_before_exec(self):
        child = Mock(pid=987654); child.wait.return_value = 0
        with patch.object(a.subprocess, "Popen", return_value=child) as spawn, patch.object(a.os, "killpg", side_effect=self.group_gone), patch.object(a.signal, "pthread_sigmask", return_value={signal.SIGUSR1}) as masks:
            a.Commands(self.root).run("mask", ["FIXTURE-never-real-command"])
            spawn.call_args.kwargs["preexec_fn"]()
            masks.assert_any_call(signal.SIG_SETMASK, {signal.SIGUSR1})

    def test_cleanup_failure_cannot_return_successful_command(self):
        child = Mock(pid=987654); child.wait.return_value = 0
        with patch.object(a.subprocess, "Popen", return_value=child), patch.object(a.os, "killpg", return_value=None), patch.object(a.time, "sleep", return_value=None):
            runner = a.Commands(self.root)
            with self.assertRaisesRegex(ValueError, "cleanup failed"):
                runner.run("cleanup-fail", ["FIXTURE-never-real-command"])
        self.assertEqual(json.loads((self.root / "commands.json").read_text())[0]["cleanup"], "FAIL")

    def test_expired_deadline_refuses_before_file_or_process_creation(self):
        with patch.object(a.time, "monotonic", side_effect=[0, 2]):
            runner = a.Commands(self.root, seconds=1)
            with self.assertRaisesRegex(ValueError, "deadline"):
                runner.run("late", ["FIXTURE-never-real-command"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cancellation_during_cleanup_cannot_preserve_success(self):
        handlers = {}
        def remember(signum, handler):
            previous = handlers.get(signum, signal.SIG_DFL)
            handlers[signum] = handler
            return previous
        def cancelled_stop(runner):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            runner.child = None
            return True
        child = Mock(pid=987654); child.wait.return_value = 0
        with patch.object(a.subprocess, "Popen", return_value=child), patch.object(a.signal, "signal", side_effect=remember), patch.object(a.Commands, "stop", autospec=True, side_effect=cancelled_stop):
            with self.assertRaises(a.Cancelled):
                a.Commands(self.root).run("final-cancel", ["FIXTURE-never-real-command"])
        row = json.loads((self.root / "commands.json").read_text())[0]
        self.assertEqual((row["status"], row["cleanup"], row["cancelled"]), ("FAIL", "PASS", True))

    def test_cancellation_during_command_receipt_save_rewrites_failure(self):
        handlers, seen = {}, []
        real_save = a.save
        def remember(signum, handler):
            previous = handlers.get(signum, signal.SIG_DFL)
            handlers[signum] = handler
            return previous
        def save_then_cancel(path, rows):
            real_save(path, rows)
            seen.append(rows[0]["status"])
            if len(seen) == 1:
                handlers[signal.SIGTERM](signal.SIGTERM, None)
        child = Mock(pid=987654); child.wait.return_value = 0
        with patch.object(a.subprocess, "Popen", return_value=child), patch.object(a.os, "killpg", side_effect=self.group_gone), patch.object(a.signal, "signal", side_effect=remember), patch.object(a, "save", side_effect=save_then_cancel):
            with self.assertRaises(a.Cancelled):
                a.Commands(self.root).run("save-cancel", ["FIXTURE-never-real-command"])
        self.assertEqual(seen, ["PASS", "FAIL"])
        row = json.loads((self.root / "commands.json").read_text())[0]
        self.assertEqual((row["status"], row["cancelled"]), ("FAIL", True))

    def test_aggregate_log_budget_rejects_next_byte_without_large_allocation(self):
        child = Mock(pid=987654); child.wait.return_value = 0
        def spawn(argv, **kwargs):
            kwargs["stdout"].write(b"x")
            return child
        with patch.object(a.subprocess, "Popen", side_effect=spawn), patch.object(a.os, "killpg", side_effect=self.group_gone):
            runner = a.Commands(self.root); runner.log_bytes = 12 * 1024**2
            with self.assertRaisesRegex(ValueError, "aggregate"):
                runner.run("budget", ["FIXTURE-never-real-command"])
        self.assertEqual(json.loads((self.root / "commands.json").read_text())[0]["status"], "FAIL")


class ControllerTests(IsolatedTests):
    def args(self):
        source = self.root / "source"; source.write_bytes(b"fixture source")
        packages = self.root / "packages"; packages.write_bytes(b"gcc 1\nzlib 2\n")
        return SimpleNamespace(image="sha256:" + "a" * 64, source=source,
                               source_commit="b" * 40, expected_packages=packages,
                               expected_packages_sha256=a.sha(packages), output=self.root / "evidence")

    def test_x86_or_root_host_refuses_before_output_or_commands(self):
        args = self.args()
        for arch, uid in (("x86_64", 1000), ("aarch64", 0)):
            with self.subTest(arch=arch, uid=uid), patch.object(a.platform, "machine", return_value=arch), patch.object(a.os, "getuid", return_value=uid), self.assertRaisesRegex(ValueError, "native ARM .*nonroot"):
                a.host(args)
            self.assertFalse(args.output.exists())

    def test_setuid_or_setgid_controller_refused_before_output_or_commands(self):
        args = self.args()
        for name in ("geteuid", "getegid"):
            with self.subTest(name=name), patch.object(a.platform, "machine", return_value="aarch64"), patch.object(a.os, name, return_value=0), self.assertRaisesRegex(ValueError, "ordinary nonroot"):
                a.host(args)
            self.assertFalse(args.output.exists())

    def test_docker_endpoint_overrides_refused_before_output_or_commands(self):
        args = self.args()
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
            with self.subTest(key=key), patch.object(a.platform, "machine", return_value="aarch64"), patch.dict(a.os.environ, {key: "unreviewed-override"}), self.assertRaises(ValueError):
                a.host(args)
            self.assertFalse(args.output.exists())

    def test_only_approved_local_endpoints_reach_daemon_probe(self):
        endpoints = ('unix:///var/run/docker.sock', 'unix:///run/docker.sock',
                     'unix:///run/user/1000/docker.sock', 'tcp://remote:2375',
                     'unix:///tmp/unreviewed.sock')
        for index, endpoint in enumerate(endpoints):
            args = self.args(); args.output = self.root / f'endpoint-{index}'
            calls = []
            def command(runner, name, argv, **kwargs):
                calls.append((name, argv))
                if name == 'context':
                    return json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}]).encode()
                raise ValueError('stop after approved endpoint; no daemon contacted')
            with self.subTest(endpoint=endpoint), patch.object(a.platform, 'machine', return_value='aarch64'), \
                 patch.object(a, 'SOURCE_SHA', a.sha(args.source)), \
                 patch.object(a.Commands, 'run', autospec=True, side_effect=command), \
                 patch.object(a.Commands, 'stop', return_value=True), patch.object(a.sys, 'stdout', io.StringIO()):
                self.assertEqual(a.host(args), 1)
            self.assertEqual([name for name, _ in calls], ['context', 'daemon'] if index < 3 else ['context'])
            if index < 3:
                self.assertEqual(calls[-1][1][:2], ['docker', '--host=' + endpoint])

    def test_native_changed_source_pin_refuses_before_output_or_commands(self):
        args = self.args()
        with patch.object(a.platform, "machine", return_value="aarch64"), patch.object(a.os, "getuid", return_value=1000), patch.object(a, "SOURCE_SHA", "0" * 64), self.assertRaisesRegex(ValueError, "hash differs"):
            a.host(args)
        self.assertFalse(args.output.exists())

    def test_inside_real_guard_refuses_before_contract_reads_or_commands(self):
        record = valid_guard(); record["arch"] = "x86_64"
        with patch.object(a, "observed", return_value=record), patch.object(a, "regular", side_effect=AssertionError("Contract file read before guard")), self.assertRaisesRegex(ValueError, "native nonroot"):
            a.inside()

    def test_host_cancellation_retains_failure_without_container_creation(self):
        args = self.args()
        with patch.object(a.platform, "machine", return_value="aarch64"), patch.object(a.os, "getuid", return_value=1000), patch.object(a, "SOURCE_SHA", a.sha(args.source)), patch.object(a.Commands, "run", side_effect=a.Cancelled()), patch.object(a.sys, "stdout", io.StringIO()):
            self.assertEqual(a.host(args), 1)
        receipt = json.loads((args.output / "result.json").read_text())
        self.assertEqual(receipt["status"], "FAIL")
        self.assertEqual(receipt["container_cleanup"], "NOT CREATED")

    def test_host_cleanup_failure_overrides_mocked_success_receipt(self):
        args = self.args()
        def fake_command(runner, name, argv, **kwargs):
            if name == "context":
                return json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]).encode()
            if name == "daemon":
                return json.dumps({"Architecture": "aarch64", "OSType": "linux"}).encode()
            if name == "image":
                return json.dumps([{"Id": args.image, "Architecture": "arm64", "Config": {}}]).encode()
            if name == "container":
                contract = json.loads((args.output / "inputs/contract.json").read_text())
                a.save(args.output / "raw/result.json", {"status": "PASS", "cleanup": "PASS", "contract": contract})
                return b""
            raise AssertionError("Unexpected fixture command")
        with patch.object(a.platform, "machine", return_value="aarch64"), patch.object(a.os, "getuid", return_value=1000), patch.object(a, "SOURCE_SHA", a.sha(args.source)), patch.object(a.Commands, "run", autospec=True, side_effect=fake_command), patch.object(a.Commands, "stop", return_value=False), patch.object(a.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as cleanup, patch.object(a, "verify_result", side_effect=lambda raw, contract, *args: {**json.loads((raw / "result.json").read_text()), "receiver_verification": {"scope": "mocked receiver"}}), patch.object(a.sys, "stdout", io.StringIO()):
            self.assertEqual(a.host(args), 1)
        self.assertEqual(cleanup.call_args.args[0][:4], ["docker", "--host=unix:///var/run/docker.sock", "rm", "-f"])
        receipt = json.loads((args.output / "result.json").read_text())
        self.assertEqual(receipt["status"], "FAIL")
        self.assertEqual(receipt["controller_group_cleanup"], "FAIL")
        self.assertNotIn("error", receipt, "cleanup must be the sole fixture failure")

    def test_host_deferred_cancel_during_final_save_or_print_rewrites_failure(self):
        real_save = a.save
        for phase in ("save", "print"):
            args = self.args(); args.output = self.root / ("evidence-" + phase)
            handlers, saves, printed = {}, [], []
            def remember(signum, handler):
                previous = handlers.get(signum, signal.SIG_DFL)
                handlers[signum] = handler
                return previous
            def save_then_cancel(path, data):
                real_save(path, data)
                if path == args.output / "result.json":
                    saves.append(data["status"])
                    if phase == "save" and len(saves) == 1:
                        handlers[signal.SIGTERM](signal.SIGTERM, None)
            def print_then_cancel(payload):
                printed.append(json.loads(payload))
                if phase == "print":
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
            def fake_command(runner, name, argv, **kwargs):
                if name == "context":
                    return json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]).encode()
                if name == "daemon":
                    return json.dumps({"Architecture": "aarch64", "OSType": "linux"}).encode()
                if name == "image":
                    return json.dumps([{"Id": args.image, "Architecture": "arm64", "Config": {}}]).encode()
                if name == "container":
                    contract = json.loads((args.output / "inputs/contract.json").read_text())
                    a.save(args.output / "raw/result.json", {"status": "PASS", "cleanup": "PASS", "contract": contract})
                    return b""
                raise AssertionError("Unexpected fixture command")
            with self.subTest(phase=phase), patch.object(a.platform, "machine", return_value="aarch64"), patch.object(a, "SOURCE_SHA", a.sha(args.source)), patch.object(a.Commands, "run", autospec=True, side_effect=fake_command), patch.object(a.Commands, "stop", return_value=True), patch.object(a.subprocess, "run", return_value=SimpleNamespace(returncode=0)), patch.object(a, "verify_result", side_effect=lambda raw, contract, *args: {**json.loads((raw / "result.json").read_text()), "receiver_verification": {"scope": "mocked receiver"}}), patch.object(a.signal, "signal", side_effect=remember), patch.object(a, "save", side_effect=save_then_cancel), patch("builtins.print", side_effect=print_then_cancel):
                self.assertEqual(a.host(args), 1)
            self.assertEqual(saves, ["PASS", "FAIL"])
            receipt = json.loads((args.output / "result.json").read_text())
            self.assertEqual((receipt["status"], receipt["cancelled"]), ("FAIL", True))
            self.assertNotIn("status", printed[0], "stdout must never publish transient PASS")
            self.assertEqual(printed[0]["result_file"], "result.json")

    def inside_fixture(self):
        inputs, output = self.root / "inputs", self.root / "out"
        inputs.mkdir(); output.mkdir(); (self.root / "tmp").mkdir()
        for name in ("arm_c01.py", "corpus.py", "packages.lock", "zlib.tar.gz"):
            (inputs / name).write_bytes(b"gcc 1\n" if name == "packages.lock" else b"fixture")
        contract = {"purpose": a.PURPOSE, "nonce": "a" * 32, "image": "sha256:" + "b" * 64,
                    "source_commit": "c" * 40, "source_sha256": a.sha(inputs / "zlib.tar.gz"),
                    "packages_sha256": a.sha(inputs / "packages.lock"),
                    "runner_sha256": a.sha(inputs / "arm_c01.py"), "corpus_sha256": a.sha(inputs / "corpus.py")}
        a.save(inputs / "contract.json", contract)
        env = {"CACHY_ASAHI_ARM_C01": contract["nonce"], "CACHY_ASAHI_ARM_C01_CONTRACT": a.sha(inputs / "contract.json")}
        class ToolPath(type(Path())):
            def is_relative_to(self, *other):
                return True if other == ("/usr",) else super().is_relative_to(*other)
        def paths(*values):
            path = Path(*values)
            if self.root == path or self.root in path.parents:
                return path
            if str(path).startswith("/usr/bin/"):
                tool = self.root / "tools" / path.name
                tool.parent.mkdir(exist_ok=True)
                if not tool.exists():
                    tool.write_bytes(b"fixture tool; never executable")
                return ToolPath(tool)
            return self.root / str(path).lstrip("/") if str(path) in ("/inputs", "/out") or str(path).startswith("/tmp/") else path
        self.enterContext(patch.object(a, "Path", side_effect=paths))
        self.enterContext(patch.object(a, "__file__", str(inputs / "arm_c01.py")))
        self.enterContext(patch.object(a, "SOURCE_SHA", contract["source_sha256"]))
        self.enterContext(patch.object(a, "observed", return_value=valid_guard()))
        self.enterContext(patch.object(a.platform, "uname", return_value=SimpleNamespace(
            _asdict=lambda: {"system": "Linux", "machine": "aarch64", "release": "fixture"})))
        self.enterContext(patch.dict(a.os.environ, env))
        return inputs, output

    def test_inside_changed_source_refuses_before_output_mutation(self):
        inputs, output = self.inside_fixture()
        (inputs / "zlib.tar.gz").write_bytes(b"replaced source")
        with self.assertRaisesRegex(ValueError, "pin differs"):
            a.inside()
        self.assertEqual(list(output.iterdir()), [])

    def test_inside_cancellation_retains_failure_receipt_without_build(self):
        _, output = self.inside_fixture()
        with patch.object(a.Commands, "run", side_effect=a.Cancelled()):
            self.assertEqual(a.inside(), 1)
        record = json.loads((output / "result.json").read_text())
        self.assertEqual((record["status"], record["cleanup"]), ("FAIL", "PASS"))
        self.assertEqual((record["hardware_validation"], record["performance_acceptance"]), ("NOT RUN", "NOT RUN"))

    def complete_inside(self, cleanup_ok=True, include_license=True, lto_evidence=True, final_cancel=False, save_cancel=False):
        _, output = self.inside_fixture()
        def fake_extract(source, work):
            (work / "README").write_bytes(b"fixture heldout")
            if include_license:
                (work / "LICENSE").write_bytes(b"synthetic license fixture; not upstream text")
        def fake_corpus(root, heldout):
            root.mkdir(); return {"files": []}
        def fake_run(runner, name, argv, **kwargs):
            if name == "inventory":
                return b"gcc 1\n"
            if name.endswith("-build"):
                for artifact in ("libz.a", "example", "minigzip"):
                    (kwargs["cwd"] / artifact).write_bytes(b"mock bytes, never a binary")
            if name.endswith("-configure"):
                for config in ("Makefile", "zconf.h", "configure.log"):
                    (kwargs["cwd"] / config).write_bytes(config_bytes(name.split("-")[0]) if config != "zconf.h" else b"mock zconf")
            if name.endswith("-strict-compile"):
                (output / name.removesuffix("-strict-compile") / "strict-gzip").write_bytes(b"mock strict binary")
            if name.endswith("-strict-valid"):
                kwargs["target"].write_bytes(corpus.GZIP_PAYLOAD); return 0
            if name.endswith("-sample-crc"):
                kwargs["target"].write_bytes(b"mock partial output"); return 1
            if name.endswith("-sample-truncation"):
                kwargs["target"].write_bytes(corpus.GZIP_PAYLOAD); return 0
            if name.endswith("-elf"):
                return ELF_GOOD
            if name.endswith("-archive-sections"):
                return b".gnu.lto_fixture" if name.startswith("lto-") and lto_evidence else b""
            return b""
        handlers = {}
        real_save, successful_saves = a.save, []
        def remember(signum, handler):
            previous = handlers.get(signum, signal.SIG_DFL)
            handlers[signum] = handler
            return previous
        def stop(runner):
            if final_cancel:
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            return cleanup_ok
        def save_then_cancel(path, data):
            real_save(path, data)
            if save_cancel and path == output / "result.json" and data["status"] == "PASS":
                successful_saves.append(True)
                if len(successful_saves) == 1:
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
        with patch.object(a, "extract", side_effect=fake_extract), patch.object(a.corpus, "create", side_effect=fake_corpus), patch.object(a.Commands, "run", autospec=True, side_effect=fake_run), patch.object(a.Commands, "stop", autospec=True, side_effect=stop), patch.object(a.signal, "signal", side_effect=remember), patch.object(a, "save", side_effect=save_then_cancel):
            result = a.inside()
        report = json.loads((output / "result.json").read_text())
        return result, report, output

    def test_inside_cleanup_failure_returns_failure_even_after_mocked_correct_builds(self):
        result, report, output = self.complete_inside(cleanup_ok=False)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(len(report["builds"]), 4, "fixture must reach all builds before cleanup")
        self.assertEqual(report["reproducibility"], {"baseline": "PASS", "lto": "PASS"})
        self.assertNotIn("error", report, "cleanup must be the sole fixture failure")
        self.assertEqual(result, 1, "cleanup failure must override pending success return")
        self.assertEqual((output / "lto-2/LICENSE.txt").read_bytes(), b"synthetic license fixture; not upstream text")

    def test_inside_missing_notice_fails_before_successful_build_record(self):
        result, report, _ = self.complete_inside(include_license=False)
        self.assertEqual((result, report["status"]), (1, "FAIL"))
        self.assertEqual(report["builds"], [])
        self.assertIn("error", report)

    def test_missing_lto_archive_evidence_cannot_pass_from_declared_flags(self):
        result, report, _ = self.complete_inside(lto_evidence=False)
        self.assertEqual((result, report["status"]), (1, "FAIL"))
        self.assertEqual([b["variant"] for b in report["builds"]], ["baseline", "baseline"])
        self.assertIn("error", report)

    def test_inside_deferred_cleanup_cancellation_overrides_completed_mock_builds(self):
        result, report, _ = self.complete_inside(final_cancel=True)
        self.assertEqual((result, report["status"], report["cancelled"]), (1, "FAIL", True))
        self.assertEqual(len(report["builds"]), 4)
        self.assertNotIn("error", report)

    def test_inside_cancel_during_first_final_pass_save_rewrites_failure(self):
        result, report, _ = self.complete_inside(save_cancel=True)
        self.assertEqual((result, report["status"], report["cancelled"]), (1, "FAIL", True))
        self.assertEqual(len(report["builds"]), 4)
        self.assertNotIn("error", report)


class ReceiverTests(IsolatedTests):
    def receipt(self):
        raw = self.root / "raw"; raw.mkdir()
        inputs = self.root / "inputs"; inputs.mkdir()
        packages = b"gcc 1\nzlib 2\n"
        (inputs / "packages.lock").write_bytes(packages)
        license_bytes, heldout = b"synthetic notice; not upstream license text\n", b"synthetic public heldout fixture\n"
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as stream:
            for name, data in (("LICENSE", license_bytes), ("README", heldout)):
                member = tarfile.TarInfo("zlib-1.3.2/" + name); member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        source = archive.getvalue()
        (inputs / "zlib.tar.gz").write_bytes(source)
        self.enterContext(patch.object(a, "SOURCE_SHA", hashlib.sha256(source).hexdigest()))
        contract = {"purpose": a.PURPOSE, "nonce": "a" * 32, "image": "sha256:" + "b" * 64,
                    "source_commit": "c" * 40, "source_sha256": a.SOURCE_SHA,
                    "packages_sha256": hashlib.sha256(packages).hexdigest(), "runner_sha256": a.sha(Path(a.__file__).resolve()), "corpus_sha256": a.sha(Path(corpus.__file__).resolve())}
        manifest = corpus.create(raw / "corpus", heldout)
        a.save(raw / "corpus-manifest.json", manifest)
        environment = {"observed": valid_guard(), "page_size": 4096,
                       "kernel": {"system": "Linux", "machine": "aarch64", "release": "synthetic"},
                       "python": "synthetic fixture", "zlib_runtime": "synthetic fixture",
                       "tool_files": {name: {"path": "/usr/bin/" + name, "sha256": "a" * 64} for name in a.TOOLS}}
        a.save(raw / "environment.json", environment)
        (raw / "strict-gzip.c").write_bytes(a.STRICT_DRIVER)
        builds = []
        for variant in ("baseline", "lto"):
            for attempt in (1, 2):
                directory = raw / f"{variant}-{attempt}"; directory.mkdir()
                for name in ("libz.a", "example", "minigzip"):
                    (directory / name).write_bytes(f"synthetic {variant} {name}; not a native binary".encode())
                    (directory / name).chmod(0o644 if name == "libz.a" else 0o755)
                (directory / "strict-gzip").write_bytes(f"synthetic {variant} strict driver".encode())
                (directory / "strict-gzip").chmod(0o755)
                generated = {}
                for name in a.CONFIG_FILES:
                    path = directory / (name + ".txt")
                    path.write_bytes(license_bytes if name == "LICENSE" else config_bytes(variant) if name in ("Makefile", "configure.log") else b"synthetic configuration\n")
                    generated[name] = a.sha(path)
                cflags, ldflags = a.build_flags(variant)
                builds.append({"variant": variant, "attempt": attempt, "artifacts": a.artifacts(directory),
                               "cflags": cflags, "ldflags": ldflags, "configured_flags": a.configured_flags(config_bytes(variant), config_bytes(variant), variant), "generated_configuration_sha256": generated,
                               "elf": a.elf_layout(ELF_GOOD), "strict_driver": {"source_sha256": a.STRICT_SHA, "binary_sha256": a.sha(directory / "strict-gzip"), "elf": a.elf_layout(ELF_GOOD)}})
        names = [f"{row['variant']}-{row['attempt']}" for row in builds]
        checks = []
        for build in names:
            for row in manifest["files"]:
                for decoder in names:
                    if row["kind"] == "corrupt":
                        checks.append({"build": build, "input": row["path"], "decoder": decoder, "driver": "strict-zlib-inflate", "rejected_exit": 2})
                    else:
                        for level in (1, 6, 9):
                            checks.append({"build": build, "input": row["path"], "level": level, "decoder": decoder,
                                           "status": "PASS", "decoded_sha256": row["sha256"]})
        bindings = {"/tmp/corpus/" + row["path"]: {"path": "/tmp/corpus/" + row["path"], "sha256": row["sha256"], "bytes": row["bytes"]}
                    for row in manifest["files"]}
        rows_by_stem = {Path(row["path"]).stem: row for row in manifest["files"]}
        commands = []
        for index, planned in enumerate(a.command_plan(manifest), 1):
            name = planned["name"]
            data = packages if name == "inventory" else ELF_GOOD if name.endswith("-elf") else (
                b".gnu.lto_fixture\n" if name.startswith("lto-") else b"no LTO sections\n") if name.endswith("-archive-sections") else b"synthetic retained command log\n"
            log = raw / f"{index:03d}-{name}.log"; log.write_bytes(data)
            row = {key: planned[key] for key in ("name", "argv", "cwd", "environment")}
            row.update(log=log.name, log_sha256=a.sha(log), log_bytes=len(data), status="PASS", cleanup="PASS",
                       exit_code=2 if planned["reject"] else 1 if planned["sample"] else 0,
                       allowed_exit_codes=[2] if planned["reject"] else list(range(1,256)) if planned["sample"] else [0,1] if planned["observe"] else [0],
                       stdin=bindings.get(planned["source"]), stdout=None)
            if planned["target"]:
                if planned["reject"] or planned["sample"] or planned["observe"] or name.endswith("-strict-valid"):
                    target = raw / Path(planned["target"]).name; target.write_bytes(corpus.GZIP_PAYLOAD if name.endswith("-strict-valid") else b"synthetic partial output")
                    digest, size = a.sha(target), target.stat().st_size
                elif "-decode-" in name:
                    stem = name.split("-decode-", 1)[0].rsplit("-", 1)[0].split("-", 2)[2]
                    original = rows_by_stem[stem]; digest, size = original["sha256"], original["bytes"]
                else:
                    digest, size = hashlib.sha256(name.encode()).hexdigest(), 100
                row["stdout"] = {"path": planned["target"], "sha256": digest, "bytes": size}
                bindings[planned["target"]] = row["stdout"]
            commands.append(row)
        a.save(raw / "commands.json", commands)
        report = {"purpose": a.PURPOSE, "status": "PASS", "contract": contract, "cleanup": "PASS",
                  "selected_for_release": False, "hardware_validation": "NOT RUN", "performance_acceptance": "NOT RUN",
                  "environment_sha256": a.sha(raw / "environment.json"), "corpus_manifest_sha256": a.sha(raw / "corpus-manifest.json"),
                  "builds": builds, "correctness": checks, "reproducibility": {"baseline": "PASS", "lto": "PASS"},
                  "strict_driver_source_sha256": a.STRICT_SHA,
                  "strict_valid": [{"decoder": name, "status": "PASS", "decoded_sha256": hashlib.sha256(corpus.GZIP_PAYLOAD).hexdigest()} for name in names],
                  "sample_crc": [{"decoder": name, "status": "PASS", "exit_code": 1} for name in names],
                  "sample_truncation": [{"decoder": name, "status": "OBSERVED", "exit_code": 0, "rejection_acceptance": "NOT CLAIMED"} for name in names]}
        a.save(raw / "result.json", report)
        return raw, contract, report, manifest, commands

    def test_complete_synthetic_receiver_fixture_without_native_execution(self):
        raw, contract, report, _, _ = self.receipt()
        self.assertEqual(sum("level" in row for row in report["correctness"]), 336)
        self.assertEqual(sum("rejected_exit" in row for row in report["correctness"]), 32)
        verified = a.verify_result(raw, contract)
        self.assertEqual({k: v for k, v in verified.items() if k != "receiver_verification"}, report)
        self.assertEqual(verified["receiver_verification"]["command_count"], 505)
        packages = (self.root / "inputs/packages.lock").read_bytes()
        source = (self.root / "inputs/zlib.tar.gz").read_bytes()
        self.assertEqual(a.verify_result(raw, contract, packages, source)["receiver_verification"], verified["receiver_verification"])

    def test_omitted_or_duplicate_build_receipts_refused(self):
        raw, contract, report, _, _ = self.receipt()
        for builds in (report["builds"][:-1], [report["builds"][0]] * 4):
            altered = copy.deepcopy(report); altered["builds"] = builds
            a.save(raw / "result.json", altered)
            with self.subTest(count=len(builds)), self.assertRaises(ValueError):
                a.verify_result(raw, contract)

    def test_omitted_corpus_and_retained_bytes_drift_refused(self):
        raw, contract, _, manifest, _ = self.receipt()
        altered = copy.deepcopy(manifest); altered["files"].pop()
        a.save(raw / "corpus-manifest.json", altered)
        a.save(raw / "corpus/manifest.json", altered)
        with self.assertRaisesRegex(ValueError, "corpus"):
            a.verify_result(raw, contract)
        a.save(raw / "corpus-manifest.json", manifest)
        a.save(raw / "corpus/manifest.json", manifest)
        (raw / "corpus/onebyte.bin").write_bytes(b"z")
        with self.assertRaisesRegex(ValueError, "corpus differs"):
            a.verify_result(raw, contract)

    def test_omitted_duplicate_or_bad_decoded_hash_checks_refused(self):
        raw, contract, report, _, _ = self.receipt()
        for mode in ("omitted", "duplicate", "decoded-hash"):
            altered = copy.deepcopy(report)
            if mode == "omitted":
                altered["correctness"].pop(0)
            elif mode == "duplicate":
                altered["correctness"].append(copy.deepcopy(altered["correctness"][0]))
            else:
                altered["correctness"][0]["decoded_sha256"] = "0" * 64
            a.save(raw / "result.json", altered)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                a.verify_result(raw, contract)

    def test_retained_artifact_hash_and_missing_notice_refused(self):
        raw, contract, _, _, _ = self.receipt()
        artifact = raw / "lto-1/minigzip"; before = artifact.read_bytes()
        artifact.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifacts"):
            a.verify_result(raw, contract)
        artifact.write_bytes(before)
        (raw / "lto-1/LICENSE.txt").unlink()
        with self.assertRaises(OSError):
            a.verify_result(raw, contract)

    def test_rebuild_pair_mismatch_cannot_use_declared_reproducibility_pass(self):
        raw, contract, report, _, _ = self.receipt()
        (raw / "baseline-2/minigzip").write_bytes(b"different second-build bytes")
        report["builds"][1]["artifacts"] = a.artifacts(raw / "baseline-2")
        a.save(raw / "result.json", report)
        with self.assertRaises(ValueError):
            a.verify_result(raw, contract)

    def test_command_status_cleanup_and_log_hash_drift_refused(self):
        raw, contract, _, _, commands = self.receipt()
        for mode in ("missing", "status", "cleanup", "hash"):
            altered = copy.deepcopy(commands)
            if mode == "missing":
                altered = []
            elif mode in ("status", "cleanup"):
                altered[0][mode] = "FAIL"
            else:
                altered[0]["log_sha256"] = "0" * 64
            a.save(raw / "commands.json", altered)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                a.verify_result(raw, contract)

    def test_corruption_rejections_missing_or_success_exit_refused(self):
        raw, contract, report, _, _ = self.receipt()
        for mode in ("missing", "success"):
            altered = copy.deepcopy(report)
            index = next(i for i, row in enumerate(altered["correctness"]) if "rejected_exit" in row)
            if mode == "missing":
                altered["correctness"].pop(index)
            else:
                altered["correctness"][index]["rejected_exit"] = 0
            a.save(raw / "result.json", altered)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                a.verify_result(raw, contract)

    def test_receiver_requires_full_command_identities_and_exits(self):
        raw, contract, _, _, commands = self.receipt()
        for mode in ("one-fake", "omit", "duplicate", "argv", "cwd", "environment", "exit", "signal-exit", "log-name", "log-size"):
            changed = copy.deepcopy(commands)
            if mode == "one-fake":
                changed = [changed[0]]
            elif mode == "omit":
                changed.pop(7)
            elif mode == "duplicate":
                changed[7] = copy.deepcopy(changed[6])
            elif mode == "signal-exit":
                next(r for r in changed if "-reject-" in r["name"])["exit_code"] = -9
            else:
                row = changed[6]
                key = {"log-name": "log", "log-size": "log_bytes", "exit": "exit_code"}.get(mode, mode)
                row[key] = ["false-command"] if mode == "argv" else {} if mode == "environment" else 123 if mode in ("exit", "log-size") else "wrong"
            a.save(raw / "commands.json", changed)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                a.verify_result(raw, contract)

    def test_receiver_derives_license_heldout_and_roles_from_pinned_source(self):
        raw, contract, report, manifest, _ = self.receipt()
        path = raw / "baseline-1/LICENSE.txt"
        path.write_bytes(b"")
        changed = copy.deepcopy(report); changed["builds"][0]["generated_configuration_sha256"]["LICENSE"] = a.sha(path)
        a.save(raw / "result.json", changed)
        with self.assertRaisesRegex(ValueError, "license differs"):
            a.verify_result(raw, contract)
        path.write_bytes(b"synthetic notice; not upstream license text\n"); a.save(raw / "result.json", report)
        for mode in ("heldout", "role"):
            changed = copy.deepcopy(manifest)
            row = next(r for r in changed["files"] if r["path"] == "heldout-source.bin")
            if mode == "role":
                row["role"] = "train"
            else:
                path = raw / "corpus/heldout-source.bin"; path.write_bytes(b"self-modified corpus")
                row.update(bytes=path.stat().st_size, sha256=a.sha(path))
            a.save(raw / "corpus/manifest.json", changed); a.save(raw / "corpus-manifest.json", changed)
            altered = copy.deepcopy(report); altered["corpus_manifest_sha256"] = a.sha(raw / "corpus-manifest.json")
            a.save(raw / "result.json", altered)
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "independent source derivation"):
                a.verify_result(raw, contract)

    def test_receiver_environment_flags_config_elf_and_lto_are_required(self):
        raw, contract, report, _, commands = self.receipt()
        original_env = (raw / "environment.json").read_bytes()
        environment = json.loads(original_env)
        for mode in ("native", "page", "tools", "env-hash", "flags", "config", "elf-receipt", "elf-log", "lto-log"):
            altered = copy.deepcopy(report)
            changed_commands = copy.deepcopy(commands)
            changed_env = copy.deepcopy(environment)
            if mode == "native":
                changed_env["observed"]["arch"] = "x86_64"
            elif mode == "page":
                changed_env["page_size"] = 123
            elif mode == "tools":
                changed_env["tool_files"].pop("ldd")
            elif mode == "flags":
                altered["builds"][0]["cflags"] += " -O3"
            elif mode == "config":
                altered["builds"][0]["generated_configuration_sha256"].pop("Makefile")
            elif mode == "elf-receipt":
                altered["builds"][0]["elf"] = {}
            elif mode in ("elf-log", "lto-log"):
                name = "baseline-1-elf" if mode == "elf-log" else "lto-1-archive-sections"
                row = next(r for r in changed_commands if r["name"] == name)
                path = raw / row["log"]
                before = path.read_bytes(); path.write_bytes(b"self-updated non-native evidence")
                row.update(log_sha256=a.sha(path), log_bytes=path.stat().st_size)
            a.save(raw / "environment.json", changed_env)
            altered["environment_sha256"] = "0" * 64 if mode == "env-hash" else a.sha(raw / "environment.json")
            a.save(raw / "result.json", altered); a.save(raw / "commands.json", changed_commands)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                a.verify_result(raw, contract)
            if mode in ("elf-log", "lto-log"):
                path.write_bytes(before)
        (raw / "environment.json").write_bytes(original_env)

    def test_effective_configured_flags_reject_self_updated_contradictions(self):
        raw, contract, report, _, _ = self.receipt()
        root = raw / "lto-1"
        original = config_bytes("lto")
        for mode in ("optimization", "lto", "isa", "tool", "mismatch", "duplicate", "linker", "receipt", "newline", "shared-seed", "missing-seed"):
            altered = copy.deepcopy(report)
            data = original
            if mode == "optimization":
                data = data.replace(b"-O2", b"-O3")
            elif mode == "lto":
                data = data.replace(b"-flto=2", b"-fno-lto")
            elif mode == "isa":
                data = data.replace(b"-march=armv8-a", b"-march=native")
            elif mode == "tool":
                data = data.replace(b"CC=gcc", b"CC=clang")
            elif mode == "duplicate":
                data += b"CFLAGS=-O3\n"
            elif mode == "linker":
                data += b"LDFLAGS=-fno-lto\n"
            elif mode == "receipt":
                altered["builds"][2]["configured_flags"]["CFLAGS"] += " -O3"
            elif mode == "newline":
                data = data.replace(b"CFLAGS=", b"CFLAGS=\n")
            elif mode == "shared-seed":
                data = data.replace(b"-frandom-seed=$@", b"-frandom-seed=shared")
            elif mode == "missing-seed":
                data = data.replace(b" -frandom-seed=$@", b"")
            for name in ("Makefile", "configure.log"):
                path = root / (name + ".txt")
                path.write_bytes(data if mode != "mismatch" or name == "Makefile" else original.replace(b"-O2", b"-O3"))
                altered["builds"][2]["generated_configuration_sha256"][name] = a.sha(path)
            a.save(raw / "result.json", altered)
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "configured|effective|final"):
                a.verify_result(raw, contract)
        for variant in ("baseline", "lto"):
            effective = a.configured_flags(config_bytes(variant), config_bytes(variant), variant)
            self.assertIn("-fPIC", effective["CFLAGS"])
            self.assertIn("-DHAVE_HIDDEN", effective["CFLAGS"])

    def test_random_seed_is_common_literal_and_unique_per_make_output_target(self):
        seeds = []
        for variant in ("baseline", "lto"):
            cflags, _ = a.build_flags(variant)
            self.assertEqual(cflags.split().count("-frandom-seed=$@"), 1)
            configured = a.configured_flags(config_bytes(variant), config_bytes(variant), variant)
            self.assertIn("-frandom-seed=$@", configured["CFLAGS"])
            targets = ("adler32.o", "crc32.o", "minigzip.o", "example.o")
            expanded = [next(flag for flag in configured["CFLAGS"].replace("$@", target).split()
                             if flag.startswith("-frandom-seed=")) for target in targets]
            self.assertEqual(expanded, ["-frandom-seed=" + target for target in targets])
            self.assertEqual(len(set(expanded)), len(targets))
            seeds.append(expanded)
        self.assertEqual(seeds[0], seeds[1], "the seed control must not introduce a variant difference")

    def test_receiver_dataflow_and_independent_inputs_cannot_be_self_asserted(self):
        raw, contract, _, _, commands = self.receipt()
        for field in ("stdin", "stdout"):
            altered = copy.deepcopy(commands)
            row = next(r for r in altered if "-decode-" in r["name"])
            row[field] = {**row[field], "sha256": "0" * 64}
            a.save(raw / "commands.json", altered)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "dataflow|decoded"):
                a.verify_result(raw, contract)
        a.save(raw / "commands.json", commands)
        for path in (self.root / "inputs/packages.lock", self.root / "inputs/zlib.tar.gz"):
            before = path.read_bytes(); path.write_bytes(b"changed independent input")
            with self.subTest(path=path), self.assertRaises(ValueError):
                a.verify_result(raw, contract)
            path.write_bytes(before)

    def test_receiver_helper_pins_and_missing_environment_are_refused(self):
        raw, contract, _, _, _ = self.receipt()
        for key in ("runner_sha256", "corpus_sha256"):
            changed = {**contract, key: "0" * 64}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "helper source"):
                a.verify_result(raw, changed)
        (raw / "environment.json").unlink()
        with self.assertRaises(OSError):
            a.verify_result(raw, contract)

    def test_strict_source_binary_positive_and_rejections_cannot_be_substituted(self):
        raw, contract, report, _, commands = self.receipt()
        original_source = (raw / "strict-gzip.c").read_bytes()
        original_binary = (raw / "baseline-1/strict-gzip").read_bytes()
        for mode in ("source", "binary", "valid-output", "valid-check", "resource-exit", "sample-driver", "truncation-pass"):
            changed, records = copy.deepcopy(report), copy.deepcopy(commands)
            if mode == "source":
                (raw / "strict-gzip.c").write_bytes(b"self-substituted driver")
                changed["strict_driver_source_sha256"] = a.sha(raw / "strict-gzip.c")
            elif mode == "binary":
                (raw / "baseline-1/strict-gzip").write_bytes(b"different binary")
            elif mode == "valid-output":
                (raw / "baseline-1-strict-valid.bin").write_bytes(b"wrong payload")
            elif mode == "valid-check":
                changed["strict_valid"].pop()
            elif mode == "resource-exit":
                next(r for r in records if "-reject-" in r["name"])["exit_code"] = 3
            elif mode == "sample-driver":
                next(r for r in records if "-reject-" in r["name"])["argv"] = ["/out/baseline-1/minigzip", "-d"]
            else:
                changed["sample_truncation"][0].update(status="PASS", rejection_acceptance="PASS")
            a.save(raw / "result.json", changed); a.save(raw / "commands.json", records)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                a.verify_result(raw, contract)
            (raw / "strict-gzip.c").write_bytes(original_source)
            (raw / "baseline-1/strict-gzip").write_bytes(original_binary)
            (raw / "baseline-1-strict-valid.bin").write_bytes(corpus.GZIP_PAYLOAD)

    def test_strict_api_and_sample_observations_have_distinct_graph_roles(self):
        raw, contract, _, manifest, _ = self.receipt()
        plans = a.command_plan(manifest)
        self.assertEqual(sum(r["reject"] for r in plans), 32)
        self.assertEqual(sum(r["sample"] for r in plans), 4)
        self.assertEqual(sum(r["observe"] for r in plans), 4)
        self.assertTrue(all(r["argv"][0].endswith("/strict-gzip") for r in plans if r["reject"]))
        verified = a.verify_result(raw, contract)["receiver_verification"]
        self.assertEqual((verified["command_count"], verified["strict_valid_count"], verified["rejection_count"]), (505, 4, 32))
        self.assertEqual(verified["sample_truncation_observation_count"], 4)

    def test_receiver_refuses_hardware_or_release_claims_and_contract_drift(self):
        raw, contract, report, _, _ = self.receipt()
        for key, value in (("hardware_validation", "PASS"), ("performance_acceptance", "PASS"),
                           ("selected_for_release", True), ("contract", {"unbound": True})):
            altered = copy.deepcopy(report); altered[key] = value
            a.save(raw / "result.json", altered)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "software-only"):
                a.verify_result(raw, contract)


if __name__ == "__main__":
    unittest.main()
