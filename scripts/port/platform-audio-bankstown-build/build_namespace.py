#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fixed host build/package namespace; upstream build code is authorized here."""
import importlib.util
import json
import os
import sys

spec=importlib.util.spec_from_file_location('held_namespace_policy','/bootstrap.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
HELD_INSTRUCTIONS=p.instructions


def build_instructions():
    rows=HELD_INSTRUCTIONS()
    # The only created socket descriptors are unnamed AF_UNIX pairs: socket()
    # and connect() remain denied and no socket FDs are inherited. Permit the
    # read/write messaging calls used by Rust's CLOEXEC child-error channel.
    for number in (44,45,46,47):
        index=rows.index((0x15,0,1,number));rows=rows[:index]+rows[index+2:]
    for i,row in enumerate(rows):
        if row==(0x15,0,1,53):
            # Rust's process launcher uses unnamed local socket pairs. Permit
            # AF_UNIX pairs only; network socket/connect calls stay denied.
            return rows[:i]+[(0x15,0,4,53),(0x20,0,0,16),(0x15,1,0,1),
                (0x06,0,0,0x00050001),(0x06,0,0,0x7fff0000)]+rows[i+2:]
    raise ValueError('HELD_SOCKETPAIR_POLICY_SHAPE_DIFFERS')


p.instructions=build_instructions
TARGET='x86_64-unknown-linux-gnu'
OPS={'metadata':['/tool/bin/cargo','metadata','--format-version','1','--locked','--offline','--filter-platform',TARGET,
                 '--manifest-path','/sources/bankstown/Cargo.toml','--quiet','--color','never'],
     'build':['/tool/bin/cargo','build','--manifest-path','/sources/bankstown/Cargo.toml','--target',TARGET,'--release','--locked','--offline','--jobs','1'],
     'package':['/usr/bin/bash','--noprofile','--norc','/package-driver.sh']}


def main():
    p.need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'TRUSTED_BOOTSTRAP_FLAGS_REQUIRED')
    p.need(len(sys.argv)==3 and sys.argv[1]in OPS,'FIXED_HOST_BUILD_OPERATION_REQUIRED')
    p.need(os.stat('/proc/self/ns/net').st_ino!=int(sys.argv[2]),'DISTINCT_NETWORK_NAMESPACE_REQUIRED')
    for path in ('/sources','/vendor'):p.remount(path,True)
    for path in ('/home','/tmp'):p.remount(path,False)
    # Build scripts/proc-macro DSOs must run from this one writable build mount.
    flags=p.MS_REMOUNT|p.MS_BIND|p.MS_NOSUID|p.MS_NODEV
    p.checked(p.LIBC.mount(None,b'/work',None,p.ctypes.c_ulong(flags),None),'EXECUTABLE_BUILD_WORKSPACE_REQUIRED')
    p.need(not os.statvfs('/work').f_flag&os.ST_NOEXEC,'EXECUTABLE_BUILD_WORKSPACE_REQUIRED')
    p.remount('/work/exec-probe',True);p.remount('/',True);p.remount('/dev',True);p.remount('/proc',True)
    p.drop_capabilities();p.restrict_syscalls();p.denial_probes();os.umask(0o077)
    print(json.dumps(dict(bankstown_build_isolation=dict(source_vendor_readonly_noexec=True,one_writable_executable_build_workspace=True,
        network_denied=True,namespace_changes_denied=True,capabilities_zero=True,seccomp=True,no_new_privs=True,
        audio_devices_absent=not os.path.exists('/dev/snd'),host_services_absent=not os.path.exists('/run')))),flush=True)
    os.execve(OPS[sys.argv[1]][0],OPS[sys.argv[1]],dict(os.environ))


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError)as error:
        print(json.dumps(dict(bankstown_build_isolation_refused=True,requirement=str(error)if type(error)is ValueError else 'HOST_BUILD_NAMESPACE_RUNTIME_REQUIRED')))
        sys.exit(78)
