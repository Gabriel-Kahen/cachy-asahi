# SPDX-License-Identifier: MIT
"""Actor-fenced models of the sealed guest storage selector."""

import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest

GUEST = Path(__file__).with_name("guest.sh")
NONCE = "1" * 32
SCRATCH_UUID = "11111111-1111-4111-8111-111111111111"
RESULT_UUID = "22222222-2222-4222-8222-222222222222"
SCRATCH_SIZE, RESULT_SIZE = 16 << 30, 64 << 20
BASH = ["/usr/bin/bash", "--noprofile", "--norc", "-s"]
ENV = {"PATH": "/qt-md4c-test-no-executables", "BASH_ENV": "/dev/null", "LC_ALL": "C"}
ACTIVE = False


def audit_fence(event, args):
    if not ACTIVE:
        return
    if event == "subprocess.Popen":
        executable, argv, cwd, env = args
        if executable == BASH[0] and argv == BASH and cwd is None and env == ENV:
            return
        raise ValueError("Storage control permits only the exact isolated Bash fixture")
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {
        "os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn", "os.mkdir",
        "os.rename", "os.link", "os.symlink", "os.remove", "os.rmdir", "os.chmod",
        "os.truncate", "os.chown", "fcntl.ioctl",
    }:
        raise ValueError("Storage control refused actor, socket, or mutation")
    if event == "open":
        path, _, flags = args
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
            if type(path) is not int or not stat.S_ISFIFO(os.fstat(path).st_mode):
                raise ValueError("Storage control refused writable file")


def bash(script):
    global ACTIVE
    ACTIVE = True
    try:
        return subprocess.run(BASH, input=("set -euo pipefail\n" + script).encode(), env=ENV,
                              capture_output=True, timeout=5, start_new_session=True)
    finally:
        ACTIVE = False


def function(source, name):
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n", source, re.M | re.S)
    if match is None:
        raise ValueError(f"Storage definition missing: {name}")
    return match[0]


MOCKS = r"""
blkid() {
    [[ $# == 6 ]] || return 99
    local field
    if [[ $1 == -c && $2 == /dev/null && $3 == -t && $5 == -o && $6 == device ]]; then
        case $4 in
            "UUID=$scratch_uuid") field=scratch_lookup ;;
            "UUID=$result_uuid") field=result_lookup ;;
            LABEL=QT16K_WORK) field=scratch_label_lookup ;;
            LABEL=QT16K_MD4C) field=result_label_lookup ;;
            *) return 99 ;;
        esac
        [[ -n ${!field} ]] || return 2
    else
        [[ $1 == -p && $2 == -s && $4 == -o && $5 == value ]] || return 99
        disk_role "$6" || return 99
        case $3 in
            UUID) field="${role}_probe_uuid" ;;
            LABEL|TYPE) field="${role}_${3,,}" ;;
            *) return 99 ;;
        esac
    fi
    printf '%s\n' "${!field}"
}
disk_role() {
    case $1 in
        "$scratch_disk") role=scratch ;;
        "$result_disk") role=result ;;
        *) return 99 ;;
    esac
}
whole_virtio() {
    disk_role "$1" || return 1
    local field="${role}_node"
    [[ -n ${!field} ]] && printf '%s\n' "${!field}"
}
flat_whole() {
    [[ $1 != "$boot_node" && $1 != "$partitioned_node" ]]
}
blockdev() {
    disk_role "$2" || return 99
    local field
    case $1 in
        --getro) field="${role}_ro" ;;
        --getsize64) field="${role}_size" ;;
        *) return 99 ;;
    esac
    printf '%s\n' "${!field}"
}
sleep() {
    [[ $# == 1 && $1 == 0.2 ]]
}

work='' result=''
if select_storage; then
    printf 'SELECTED %s %s\n' "$work" "$result"
else
    rc=$?
    printf 'UNSELECTED %s:%s\n' "$work" "$result"
    exit "$rc"
fi
"""


class StorageControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.addaudithook(audit_fence)
        cls.source = GUEST.read_text()
        cls.selector = "".join(function(cls.source, name) for name in ("storage_error", "select_storage"))

    def model(self, *, drives=("/dev/vdb", "/dev/vda", "/dev/vdc"), **overrides):
        scratch, result, boot = drives
        fields = {
            "scratch_uuid": SCRATCH_UUID, "result_uuid": RESULT_UUID, "nonce": NONCE,
            "scratch_probe_uuid": SCRATCH_UUID, "result_probe_uuid": RESULT_UUID,
            "scratch_disk": scratch, "result_disk": result,
            "scratch_lookup": scratch, "result_lookup": result,
            "scratch_label_lookup": scratch, "result_label_lookup": result,
            "scratch_label": "QT16K_WORK", "result_label": "QT16K_MD4C",
            "scratch_type": "ext4", "result_type": "ext4",
            "scratch_size": SCRATCH_SIZE, "result_size": RESULT_SIZE,
            "scratch_ro": 0, "result_ro": 0, "partitioned_node": "",
            "scratch_node": "/sys/devices/virtio1/block/" + Path(scratch).name,
            "result_node": "/sys/devices/virtio0/block/" + Path(result).name,
            "boot_node": "/sys/devices/virtio2/block/" + Path(boot).name,
        }
        fields.update(overrides)
        values = "".join(f"{key}={shlex.quote(str(value))}\n" for key, value in fields.items())
        process = bash(values + self.selector + MOCKS)
        return process.returncode, process.stdout, process.stderr

    def test_reversed_and_permuted_enumeration_selects_roles(self):
        for drives in (("/dev/vdb", "/dev/vda", "/dev/vdc"), ("/dev/vdc", "/dev/vdb", "/dev/vda")):
            with self.subTest(drives=drives):
                self.assertEqual(self.model(drives=drives), (0, f"SELECTED {drives[0]} {drives[1]}\n".encode(), b""))

    def test_storage_rejects_unbound_unwritable_and_aliasing_devices(self):
        cases = (
            ("UUID_LOOKUP", {"scratch_lookup": ""}),
            ("UUID_SELECTION", {"result_lookup": "/dev/vda\n/dev/vde"}),
            ("WHOLE_VIRTIO", {"result_node": ""}),
            ("DISK_ALIAS", {"result_lookup": "/dev/vdb"}),
            ("FLAT_DISK", {"result_node": "/sys/devices/virtio2/block/vdc"}),
            ("FLAT_DISK", {"partitioned_node": "/sys/devices/virtio1/block/vdb"}),
            ("FILESYSTEM_ID", {"scratch_label_lookup": "/dev/vde"}),
            ("FILESYSTEM_ID", {"scratch_label": "QT16K_MD4C"}),
            ("FILESYSTEM_ID", {"result_probe_uuid": SCRATCH_UUID}),
            ("FILESYSTEM_ID", {"result_type": "ext3"}),
            ("GEOMETRY", {"scratch_size": SCRATCH_SIZE - 512}),
            ("GEOMETRY", {"result_size": RESULT_SIZE + 512}),
            ("WRITE_STATE", {"scratch_ro": 1}),
            ("WRITE_STATE", {"result_ro": 1}),
        )
        for reason, overrides in cases:
            expected = f"QTMD4C16K_STORAGE {NONCE} {reason}\nUNSELECTED :\n".encode()
            with self.subTest(reason=reason, overrides=overrides):
                self.assertEqual(self.model(**overrides), (1, expected, b""))

    def test_flat_whole_and_readonly_boot(self):
        self.assertIn("findmnt -n -o VFS-OPTIONS / | grep -qw ro", self.source.split("phase=storage", 1)[0])
        with tempfile.TemporaryDirectory() as temporary:
            flat = Path(temporary) / "flat"
            partitioned = Path(temporary) / "partitioned"
            flat.mkdir()
            (partitioned / "child").mkdir(parents=True)
            (partitioned / "child/partition").write_text("1\n")
            script = (function(self.source, "flat_whole") + f"flat_whole {shlex.quote(str(flat))}\n"
                      f"! flat_whole {shlex.quote(str(partitioned))}\n")
            process = bash(script)
            self.assertEqual((process.returncode, process.stdout, process.stderr), (0, b"", b""))

    def test_fence_rejects_actor_socket_and_writable_open(self):
        global ACTIVE
        ACTIVE = True
        try:
            for event, args in (
                ("subprocess.Popen", ("qemu-system-aarch64", [], None, {})),
                ("socket.connect", ()),
                ("open", ("/dev/vda", "wb", os.O_WRONLY)),
            ):
                with self.subTest(event=event), self.assertRaisesRegex(ValueError, "Storage control"):
                    sys.audit(event, *args)
        finally:
            ACTIVE = False


if __name__ == "__main__":
    unittest.main()
