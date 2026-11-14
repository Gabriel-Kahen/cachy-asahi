#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite trusted bwrap setup for Cargo metadata; never a rustc wrapper."""
import ctypes
import errno
import json
import os
import sys

LIBC=ctypes.CDLL(None,use_errno=True)
MS_RDONLY,MS_NOSUID,MS_NODEV,MS_NOEXEC,MS_REMOUNT,MS_BIND=1,2,4,8,32,4096
PR_SET_NO_NEW_PRIVS,PR_GET_NO_NEW_PRIVS,PR_SET_SECCOMP,PR_GET_SECCOMP=38,39,22,21
DENIED=[41,42,43,44,45,46,47,49,50,51,52,53,54,55,101,155,165,166,272,288,298,308,311,319,321,322,425,428,429,430,431,432,442]
NEW_NAMESPACES=0x7e020000
OPERATIONS={'cargo-version':['/tool/bin/cargo','--version'], 'rustc-version':['/tool/bin/rustc','-vV']}
for name in ('bankstown','speakersafetyd','triforce-lv2'):
    OPERATIONS[name]=['/tool/bin/cargo','metadata','--format-version','1','--locked','--offline',
        '--filter-platform','aarch64-unknown-linux-gnu','--manifest-path','/sources/'+name+'/Cargo.toml','--quiet','--color','never']


def need(value,code):
    if not value:raise ValueError(code)


def checked(result,code):
    need(result==0,code)


def remount(path,readonly):
    flags=MS_REMOUNT|MS_BIND|MS_NOSUID|MS_NOEXEC|(MS_NODEV if path!='/dev'else 0)|(MS_RDONLY if readonly else 0)
    checked(LIBC.mount(None,path.encode(),None,ctypes.c_ulong(flags),None),'NOEXEC_REMOUNT_REFUSED:'+path)
    state=os.statvfs(path).f_flag
    need(state&os.ST_NOEXEC and(not readonly or state&os.ST_RDONLY),'NOEXEC_READONLY_STATE_UNKNOWN')


def drop_capabilities():
    for cap in range(64):
        result=LIBC.prctl(24,cap,0,0,0)  # PR_CAPBSET_DROP
        need(result==0 or ctypes.get_errno()==errno.EINVAL,'CAPABILITY_BOUNDING_DROP_REFUSED')
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    checked(LIBC.capset(ctypes.byref(Header(0x20080522,0)),(Data*2)()),'CAPABILITY_DROP_REFUSED')
    with open('/proc/self/status')as stream:lines=stream.read().splitlines()
    values={key:value.strip()for line in lines if ':'in line for key,value in [line.split(':',1)]}
    need(all(int(values[key],16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),'CAPABILITIES_REMAIN')


def instructions():
    # x86_64 only, including explicit x32 refusal. clone3 ENOSYS makes libc use
    # inspectable clone flags; ordinary threads/forks remain allowed.
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
          (0x20,0,0,0),(0x45,0,1,0x40000000),(0x06,0,0,0x00050000|errno.EPERM)]
    for number in DENIED:rows.extend([(0x15,0,1,number),(0x06,0,0,0x00050000|errno.EPERM)])
    rows.extend([(0x15,0,1,435),(0x06,0,0,0x00050000|errno.ENOSYS),
        (0x15,0,3,56),(0x20,0,0,16),(0x45,0,1,NEW_NAMESPACES),(0x06,0,0,0x00050000|errno.EPERM),(0x06,0,0,0x7fff0000)])
    return rows


def restrict_syscalls():
    class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint32)]
    class Program(ctypes.Structure):_fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    rows=instructions();storage=(Filter*len(rows))(*(Filter(*row)for row in rows))
    checked(LIBC.prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0),'NO_NEW_PRIVS_REFUSED')
    checked(LIBC.prctl(PR_SET_SECCOMP,2,ctypes.byref(Program(len(rows),storage)),0,0),'SECCOMP_REFUSED')
    need(LIBC.prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1 and LIBC.prctl(PR_GET_SECCOMP,0,0,0,0)==2,'SECCOMP_STATE_UNKNOWN')


def denial_probes():
    # This is an exact copied trusted Cargo ELF, never upstream/artifact code.
    child=os.fork()
    if child==0:
        try:os.execve('/work/exec-probe',['/work/exec-probe','--version'],dict(os.environ))
        except OSError as error:os._exit(error.errno)
        os._exit(99)
    _,status=os.waitpid(child,0)
    need(os.WIFEXITED(status)and os.WEXITSTATUS(status)==errno.EACCES,'NOEXEC_EXECUTION_PROBE_NOT_DENIED')
    fd=os.open('/work/exec-probe',os.O_RDONLY)
    try:
        LIBC.mmap.restype=ctypes.c_void_p
        result=LIBC.mmap(None,4096,5,2,fd,0)  # PROT_READ|PROT_EXEC, MAP_PRIVATE
        if result!=ctypes.c_void_p(-1).value:
            LIBC.munmap(ctypes.c_void_p(result),4096)
            raise ValueError('NOEXEC_EXECUTABLE_MAPPING_NOT_DENIED')
        need(ctypes.get_errno()in(errno.EPERM,errno.EACCES),'NOEXEC_MAPPING_STATE_UNKNOWN')
    finally:os.close(fd)
    result=LIBC.socket(2,1,0)
    if result>=0:
        os.close(result);raise ValueError('NETWORK_SOCKET_NOT_DENIED')
    need(ctypes.get_errno()==errno.EPERM,'NETWORK_DENIAL_STATE_UNKNOWN')
    need(LIBC.unshare(0x10000000)==-1 and ctypes.get_errno()==errno.EPERM,'NEW_USER_NAMESPACE_NOT_DENIED')


def main():
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'TRUSTED_PYTHON_FLAGS_REQUIRED')
    need(len(sys.argv)==3 and sys.argv[1]in OPERATIONS and sys.argv[2].isdigit(),'FIXED_METADATA_OPERATION_REQUIRED')
    need(os.stat('/proc/self/ns/net').st_ino!=int(sys.argv[2]),'NETWORK_NAMESPACE_NOT_DISTINCT')
    for path in ('/sources','/vendor'):remount(path,True)
    for path in ('/work','/home','/tmp'):remount(path,False)
    remount('/',True)
    # /dev remains usable for null/random but cannot supply an executable.
    remount('/dev',True);remount('/proc',True)
    checked(LIBC.umount2(b'/usr/bin/python3.14',2),'BOOTSTRAP_INTERPRETER_REMOVAL_REFUSED')
    drop_capabilities();restrict_syscalls();denial_probes()
    print(json.dumps(dict(metadata_isolation=dict(noexec_source_vendor_workspace=True,executable_mapping_denied=True,
        source_elf_exec_denied=True,network_socket_denied=True,new_user_namespace_denied=True,capabilities_zero=True,
        bootstrap_interpreter_removed=True,no_new_privs=True,seccomp=True))),flush=True)
    os.execve(OPERATIONS[sys.argv[1]][0],OPERATIONS[sys.argv[1]],dict(os.environ))


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError)as error:
        print(json.dumps(dict(metadata_isolation_refused=True,requirement=str(error)if type(error)is ValueError else 'NAMESPACE_RUNTIME_REQUIREMENT')))
        sys.exit(78)
