/* SPDX-License-Identifier: MIT
 * Diskless freestanding AArch64 PID1. Only read-only DM discovery ioctls.
 * Executed only inside Root's explicitly authorized disposable boot VM. */
#include "probe-uapi.h"
static char nonce[33],output[65536];
static U used;
static long console=-1;
static unsigned char io[16384] __attribute__((aligned(8)));
static long syscall6(U n,U a,U b,U c,U d,U e,U f){
 register U x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
 register U x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
 __asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory");return (long)x0;
}
static void text(const char *s){while(*s&&used<sizeof(output)-1)output[used++]=*s++;}
static void number(U n){char tmp[24];U i=0;do{tmp[i++]=(char)('0'+n%10);n/=10;}while(n);while(i&&used<sizeof(output)-1)output[used++]=tmp[--i];}
static void signed_number(long n){if(n<0){text("-");number((U)(-n));}else number((U)n);}
static int equal(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int safe_name(const char*s,U cap){U i;for(i=0;i<cap&&s[i];i++){char c=s[i];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='+'||c=='-'))return 0;}return i>0&&i<cap;}
static void begin(const char*event){used=0;text("GNU_BOOT_DM ");text(nonce);text(" {\"event\":\"");text(event);text("\"");}
static void finish(void){text("}\n");U sent=0;while(sent<used){long n=syscall6(NR_WRITE,(U)console,(U)(output+sent),used-sent,0,0,0);if(n<=0)break;sent+=(U)n;}}
static void hex(const unsigned char*p,U n){const char*h="0123456789abcdef";for(U i=0;i<n;i++){output[used++]=h[p[i]>>4];output[used++]=h[p[i]&15];}}
static void poweroff(void){syscall6(NR_SYNC,0,0,0,0,0,0);syscall6(NR_REBOOT,LINUX_REBOOT_MAGIC1,LINUX_REBOOT_MAGIC2,LINUX_REBOOT_CMD_POWER_OFF,0,0,0);}
__attribute__((noreturn)) static void fail(U stage,long result){begin("fail");text(",\"stage\":");number(stage);text(",\"rc\":");signed_number(result);finish();poweroff();syscall6(NR_EXIT_GROUP,111,0,0,0,0,0);for(;;){}}
static struct dm_ioctl*header(U size){for(U i=0;i<sizeof(io);i++)io[i]=0;struct dm_ioctl*h=(void*)io;h->version[0]=DM_MAJOR;h->version[1]=DM_MINOR;h->version[2]=DM_PATCH;h->data_size=(U32)size;h->data_start=sizeof(*h);return h;}
static int good_header(struct dm_ioctl*h,U size){return h->version[0]==4&&h->version[1]==50&&h->version[2]==0&&h->data_size>=312&&h->data_size<=size&&h->data_start==312&&!(h->flags&DM_BUFFER_FULL_FLAG);}
__attribute__((noreturn,used)) void boot_entry(U*stack){
 console=syscall6(NR_OPENAT,(U)-100,(U)"/dev/console",1|0x80000,0,0,0);if(console<0)for(;;){}
 long fd=syscall6(NR_OPENAT,(U)-100,(U)"/nonce",0x80000,0,0,0);if(fd<0)fail(1,fd);
 long n=syscall6(NR_READ,(U)fd,(U)nonce,33,0,0,0);if(n!=32)fail(2,n);nonce[32]=0;
 for(U i=0;i<32;i++)if(!((nonce[i]>='0'&&nonce[i]<='9')||(nonce[i]>='a'&&nonce[i]<='f')))fail(3,0);
 if(syscall6(NR_CLOSE,(U)fd,0,0,0,0,0)!=0)fail(4,0);
 U argc=*stack++;if(argc>32)fail(5,0);stack+=argc+1;U env=0;while(*stack&&env++<128)stack++;if(env>=128)fail(6,0);stack++;
 U page=0,entries=0;while(stack[0]&&entries++<64){if(stack[0]==AT_PAGESZ){if(page)fail(7,0);page=stack[1];}stack+=2;}if(entries>=64||stack[0])fail(7,0);
 long pid=syscall6(NR_GETPID,0,0,0,0,0,0);struct kernel_utsname uts;long rc=syscall6(NR_UNAME,(U)&uts,0,0,0,0,0);
 if(pid!=1||page!=16384||rc||!safe_name(uts.machine,65)||!safe_name(uts.release,65)||!equal(uts.machine,"aarch64")||!equal(uts.release,"7.1.13-generic16k-managed-gui"))fail(8,rc);
 begin("boot");text(",\"pid\":");number((U)pid);text(",\"page_size\":");number(page);text(",\"machine\":\"");text(uts.machine);text("\",\"kernel\":\"");text(uts.release);text("\"");finish();
 fd=syscall6(NR_OPENAT,(U)-100,(U)"/dev/mapper/control",2|0x80000,0,0,0);if(fd<0)fail(9,fd);
 struct dm_ioctl*h=header(sizeof(*h));rc=syscall6(NR_IOCTL,(U)fd,DM_IOCTL_CODE(DM_VERSION_CMD),(U)io,0,0,0);if(rc||!good_header(h,sizeof(*h)))fail(10,rc);
 begin("dm_version");text(",\"command\":");number(DM_IOCTL_CODE(DM_VERSION_CMD));text(",\"rc\":0,\"bytes\":");number(h->data_size);text(",\"raw_hex\":\"");hex(io,h->data_size);text("\"");finish();
 h=header(sizeof(io));rc=syscall6(NR_IOCTL,(U)fd,DM_IOCTL_CODE(DM_LIST_VERSIONS_CMD),(U)io,0,0,0);if(rc||!good_header(h,sizeof(io)))fail(11,rc);
 U pos=h->data_start,count=0,found=0;U32 version[3]={0,0,0};
 while(pos+17<=h->data_size&&count<64){struct dm_target_versions*v=(void*)(io+pos);U end=v->next?pos+v->next:h->data_size;if(end>h->data_size||end<=pos+16||!safe_name(v->name,end-pos-16)||v->next%8)fail(12,0);
  if(equal(v->name,"verity")){found++;for(U i=0;i<3;i++)version[i]=v->version[i];}count++;if(!v->next)break;pos=end;
 }
 if(found!=1||count==0||count>=64||version[0]!=1||version[1]!=13||version[2]!=0)fail(13,0);
 begin("dm_targets");text(",\"command\":");number(DM_IOCTL_CODE(DM_LIST_VERSIONS_CMD));text(",\"rc\":0,\"bytes\":");number(h->data_size);text(",\"count\":");number(count);text(",\"verity_version\":[1,13,0],\"raw_hex\":\"");hex(io,h->data_size);text("\"");finish();
 rc=syscall6(NR_CLOSE,(U)fd,0,0,0,0,0);if(rc)fail(14,rc);
 begin("poweroff");text(",\"pid\":1,\"method\":\"LINUX_REBOOT_CMD_POWER_OFF\",\"dm_closed\":true");finish();poweroff();fail(15,0);
}
__asm__(".global _start\n_start:\nmov x0,sp\nbl boot_entry\n1: b 1b\n");
