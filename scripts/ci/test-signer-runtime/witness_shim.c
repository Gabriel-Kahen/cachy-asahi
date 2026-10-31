/* SPDX-License-Identifier: MIT
 * Aarch64 signer-only probe launcher. Predecessor compile trial 38537449008
 * failed; this include-corrected Source is not built or executed.
 * Fixed inherited descriptors: listener194, transfer196, policy-pinned ELF197.
 * Source/native policy must admit this compiled executable before Popen.
 */
#include <asm/unistd.h>
#include <linux/ioctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/fcntl.h>

#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Only selected little-endian aarch64 ABI"
#endif
_Static_assert(__NR_execveat == 281 && __NR_brk == 214 && __NR_clone == 220, "selected ABI");
_Static_assert(__NR_clone3 == 435 && __NR_execve == 221 && __NR_seccomp == 277, "selected ABI");
_Static_assert(PR_SET_NO_NEW_PRIVS == 38 && PR_SET_SECCOMP == 22 && PR_SET_MM == 35, "selected ABI");
_Static_assert(AT_EMPTY_PATH == 4096 && BPF_LD+BPF_W+BPF_ABS == 32, "selected ABI");
_Static_assert(BPF_JMP+BPF_JEQ+BPF_K == 21 && BPF_RET+BPF_K == 6, "selected ABI");
_Static_assert(SECCOMP_IOCTL_NOTIF_RECV == 0xc0502100UL && SECCOMP_IOCTL_NOTIF_SEND == 0xc0182101UL
               && SECCOMP_IOCTL_NOTIF_ID_VALID == 0x40082102UL, "selected ioctl ABI");
_Static_assert(sizeof(struct seccomp_data) == 64 && sizeof(struct seccomp_notif) == 80, "selected ABI");

static const struct sock_filter rules[] = {
#ifdef WITNESS_SUPPORTED_THREADS
#include "thread_filter.inc"
#else
#include "exec_filter.inc"
#endif
};
static const char empty[] = "";
static long call6(long nr, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8")=nr;
    register long x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5) : "memory","cc");
    return x0;
}
__attribute__((noreturn)) static void done(long code) {
    call6(__NR_exit_group,code,0,0,0,0,0);
    for (;;) __asm__ volatile("brk #0"); /* trap instruction, NOT brk syscall */
}
__attribute__((noreturn)) static void stop(void) {done(111);}
static unsigned length(const char *s, unsigned cap) {
    unsigned n=0;while (n<cap && s[n]) ++n;if(n==cap)stop();return n;
}
static int prefix(const char *s, const char *p) {
    while (*p) {if (*s++ != *p++)return 0;}return 1;
}
struct vector { void *base; unsigned long size; };
struct message { void *name; unsigned name_size; struct vector *vectors; unsigned long count;
                 void *control; unsigned long control_size; unsigned flags; };
struct rights { unsigned long size; int level,kind,fd,padding; };
_Static_assert(sizeof(struct message)==56 && sizeof(struct rights)==24,"aarch64 message ABI");

static void diagnostic(const char *nonce, int stage, long result) {
    struct {char nonce[32];int stage,error;} payload;
    for(unsigned i=0;i<32;i++)payload.nonce[i]=nonce[i];
    payload.stage=stage;payload.error=result<0 && result>=-4095 ? (int)-result : 0;
    struct vector vector={&payload,sizeof(payload)};
    struct message message={0,0,&vector,1,0,0,0};
    call6(__NR_sendmsg,196,(long)&message,0,0,0,0);
}
__attribute__((noreturn,used)) void shim_main(unsigned long *stack) {
    unsigned long argc=stack[0];char **args=(char **)(stack+1);
    if(argc==1) {
        unsigned action=SECCOMP_RET_USER_NOTIF;struct seccomp_notif_sizes sizes;
        if(call6(__NR_seccomp,SECCOMP_GET_ACTION_AVAIL,0,(long)&action,0,0,0)<0)
            done(121);
        if(call6(__NR_seccomp,SECCOMP_GET_NOTIF_SIZES,0,(long)&sizes,0,0,0)<0
           || sizes.seccomp_notif!=80 || sizes.seccomp_notif_resp!=24 || sizes.seccomp_data!=64)
            done(122);
        if(call6(__NR_prctl,PR_SET_NO_NEW_PRIVS,1,0,0,0,0)<0)
            done(123);
        struct sock_filter allow={BPF_RET+BPF_K,0,0,SECCOMP_RET_ALLOW};
        struct sock_fprog check={1,&allow};
        long fd=call6(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,(long)&check,0,0,0);
        if(fd<0)done(124);
        if(call6(__NR_close,fd,0,0,0,0,0)<0)done(125);
        done(0);
    }
    if(argc!=3 || length(args[1],4096)==0 || length(args[2],33)!=32)stop();
    for(unsigned i=0;i<32;i++)if(!((args[2][i]>='0'&&args[2][i]<='9')||(args[2][i]>='a'&&args[2][i]<='f')))stop();
    char **incoming=args+argc+1;
    const char *names[]={"PATH=","HOME=","LANG=","LC_ALL=","GNUPGHOME=","XDG_RUNTIME_DIR="};
    char *env[10];unsigned count=0,seen=0;
    while(incoming[count]) {
        if(count>=6)stop();length(incoming[count],8192);unsigned bit=0;
        for(unsigned i=0;i<6;i++)if(prefix(incoming[count],names[i]))bit=1u<<i;
        if(!bit || (seen&bit))stop();seen|=bit;env[count]=incoming[count];count++;
    }
    if(count!=6 || seen!=63)stop();
    char pid_text[40]="LISTEN_PID=";unsigned at=11;char digits[20];unsigned n=0;
    long pid=call6(__NR_getpid,0,0,0,0,0,0);if(pid<=0)stop();
    do {digits[n++]=(char)('0'+pid%10);pid/=10;}while(pid);
    while(n)pid_text[at++]=digits[--n];pid_text[at]=0;
    env[count++]=pid_text;env[count++]="LISTEN_FDS=1";env[count++]="LISTEN_FDNAMES=std";env[count]=0;
    char *agent[]={"/usr/bin/gpg-agent","--no-options","--homedir",args[1],"--supervised",
        "--disable-scdaemon","--extra-socket","none","--browser-socket","none",
        "--allow-loopback-pinentry","--no-allow-external-cache",0};
    if(call6(__NR_dup3,194,3,0,0,0,0)<0 || call6(__NR_close,194,0,0,0,0,0)<0)stop();
    if(call6(__NR_fcntl,197,F_SETFD,FD_CLOEXEC,0,0,0)<0
       || call6(__NR_fcntl,196,F_SETFD,FD_CLOEXEC,0,0,0)<0)stop();
    if(call6(__NR_prctl,PR_SET_NO_NEW_PRIVS,1,0,0,0,0)<0)stop();
    struct sock_fprog program={sizeof(rules)/sizeof(rules[0]),(struct sock_filter *)rules};
    long listener=call6(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,(long)&program,0,0,0);
    if(listener<0) {diagnostic(args[2],1,listener);stop();}
    if(listener==3 || listener==196 || listener==197)stop();
    /* After installation: no allocation, libc, handler, brk, thread or fork path.
     * sendmsg/close failures and execveat return only send fixed diagnostics and exit_group.
     */
    struct vector vector={args[2],32};
    struct rights right={20,1,1,(int)listener,0}; /* SOL_SOCKET / SCM_RIGHTS */
    struct message message={0,0,&vector,1,&right,sizeof(right),0};
    if(call6(__NR_sendmsg,196,(long)&message,0,0,0,0)!=32)stop();
    if(call6(__NR_close,listener,0,0,0,0,0)<0)stop();
    long result=call6(__NR_execveat,197,(long)empty,(long)agent,(long)env,AT_EMPTY_PATH,0);
    diagnostic(args[2],2,result);
    stop(); /* A failed or intercepted-return exec cannot issue a brk syscall. */
}
__asm__(".global _start\n_start:\n mov x0, sp\n bl shim_main\n brk #0\n");
