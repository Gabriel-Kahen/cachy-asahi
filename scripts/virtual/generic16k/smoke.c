/* SPDX-License-Identifier: MIT
 * Freestanding AArch64 Linux page/ELF smoke, executed only inside the owned VM. */
typedef unsigned long U;
static long call(U n, U a, U b, U c, U d, U e, U f) {
    register U x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
    register U x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
    register U x8 __asm__("x8")=n;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory");
    return (long)x0;
}
static int bad(long n) { return (U)n >= (U)-4095; }
static void quit(int n) { call(93,n,0,0,0,0,0); for (;;) {} }
void entry(U *sp) {
    U argc=*sp++, *argv=sp, page=0;
    if (argc==2 && ((char *)argv[1])[0]=='p') {
        call(142,0xfee1dead,672274793,0x4321fedc,0,0,0); quit(90);
    }
    sp += argc+1; while (*sp) ++sp; ++sp;
    while (*sp) { if (sp[0]==6) page=sp[1]; sp+=2; }
    if (page!=16384) quit(10);
    long p=call(222,0,page*2,3,0x22,(U)-1,0);
    if (bad(p)) quit(11);
    ((volatile char *)p)[0]=37; ((volatile char *)p)[page]=53;
    if (call(226,p,page,1,0,0,0)!=0 || ((volatile char *)p)[0]!=37) quit(12);
    if (call(215,p,page*2,0,0,0,0)!=0) quit(13);
    long fd=call(56,(U)-100,(U)"/page-data",0,0,0,0);
    if (bad(fd)) quit(14);
    p=call(222,0,page,1,2,fd,page);
    if (bad(p) || ((volatile char *)p)[0]!='B') quit(15);
    if (call(215,p,page,0,0,0,0)!=0) quit(16);
    if (call(222,0,page,1,2,fd,4096)!=-22) quit(17);
    if (call(57,fd,0,0,0,0,0)!=0) quit(18);
    static const char ok[]="SMOKE16K: mmap,mprotect,file-offset PASS\n";
    if (call(64,1,(U)ok,sizeof(ok)-1,0,0,0)!=sizeof(ok)-1) quit(19);
    quit(0);
}
__asm__(".global _start\n_start:\nmov x0,sp\nbl entry\n");
