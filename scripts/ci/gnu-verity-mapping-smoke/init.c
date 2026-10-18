/* SPDX-License-Identifier: MIT
 * Diskless freestanding AArch64 PID1. Guest-only nonce-owned DM-verity mappings and bounded integrity smoke.
 * Executed only inside Root's explicitly authorized disposable boot VM. */
#include "probe-uapi.h"
#include "fixture-data.h"
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
static void begin(const char*event){used=0;text("GNU_VERITY_SMOKE ");text(nonce);text(" {\"event\":\"");text(event);text("\"");}
static void finish(void){text("}\n");U sent=0;while(sent<used){long n=syscall6(NR_WRITE,(U)console,(U)(output+sent),used-sent,0,0,0);if(n<=0)break;sent+=(U)n;}}
static void hex(const unsigned char*p,U n){const char*h="0123456789abcdef";for(U i=0;i<n;i++){output[used++]=h[p[i]>>4];output[used++]=h[p[i]&15];}}
static void poweroff(void){syscall6(NR_SYNC,0,0,0,0,0,0);syscall6(NR_REBOOT,LINUX_REBOOT_MAGIC1,LINUX_REBOOT_MAGIC2,LINUX_REBOOT_CMD_POWER_OFF,0,0,0);}
__attribute__((noreturn)) static void fail(U stage,long result){begin("fail");text(",\"stage\":");number(stage);text(",\"rc\":");signed_number(result);finish();poweroff();syscall6(NR_EXIT_GROUP,111,0,0,0,0,0);for(;;){}}
static struct dm_ioctl*header(U size){for(U i=0;i<sizeof(io);i++)io[i]=0;struct dm_ioctl*h=(void*)io;h->version[0]=DM_MAJOR;h->version[1]=DM_MINOR;h->version[2]=DM_PATCH;h->data_size=(U32)size;h->data_start=sizeof(*h);return h;}
static int good_header(struct dm_ioctl*h,U size){return h->version[0]==4&&h->version[1]==50&&h->version[2]==0&&h->data_size>=312&&h->data_size<=size&&h->data_start==312&&!(h->flags&DM_BUFFER_FULL_FLAG);}

static unsigned char saved[1024],block[8192],st[128] __attribute__((aligned(8)));
static const char *paths[3];
static char names[2][48];
static U64 mapdev[2];
static char *copy(char*d,const char*s){while(*s)*d++=*s++;*d=0;return d;}
static unsigned char expected(U i){return (unsigned char)(i*29+(i/4096)*71+(i/256)*3+17);}
static U32 minor_number(U64 d){return (U32)((d&255)|((d>>12)&0xfff00));}
static U64 inspect(long fd,U64 *size){
 S32 ro=0;long rc=syscall6(NR_IOCTL,(U)fd,BLKROGET,(U)&ro,0,0,0);if(rc||ro!=1)fail(20,rc);
 rc=syscall6(NR_IOCTL,(U)fd,BLKGETSIZE64,(U)size,0,0,0);if(rc||(*size!=4096&&*size!=8192))fail(21,rc);
 for(U i=0;i<128;i++)st[i]=0;rc=syscall6(NR_FSTAT,(U)fd,(U)st,0,0,0,0);if(rc||(*(U32*)(void*)(st+16)&0170000)!=0060000)fail(22,rc);
 return *(U64*)(void*)(st+32);
}
static void discover(void){
 const char *candidate[3]={"/dev/vda","/dev/vdb","/dev/vdc"};
 for(U k=0;k<3;k++){
  long fd=syscall6(NR_OPENAT,(U)-100,(U)candidate[k],0x80000,0,0,0);if(fd<0)fail(23,fd);U64 size=0,rdev=inspect(fd,&size);
  long rc=syscall6(NR_PREAD64,(U)fd,(U)block,(U)size,0,0,0);if(rc!=(long)size)fail(24,rc);U role=3;
  if(size==4096){U ok=1;for(U j=0;j<4096;j++)if(block[j]!=expected_hash[j])ok=0;if(ok)role=1;}
  else{U good=1,bad=1;for(U j=0;j<8192;j++){unsigned char e=expected(j);if(block[j]!=e)good=0;if(j==4133)e^=1;if(block[j]!=e)bad=0;}if(good)role=0;else if(bad)role=2;}
  if(role>2||paths[role])fail(25,0);paths[role]=candidate[k];
  begin("device");text(",\"role\":\"");text(role==0?"good":role==1?"hash":"bad");text("\",\"path\":\"");text(candidate[k]);text("\",\"bytes\":");number((U)size);text(",\"readonly\":1,\"rdev\":");number((U)rdev);text(",\"stat_hex\":\"");hex(st,128);text("\",\"raw_hex\":\"");hex(block,(U)size);text("\"");finish();
  if(syscall6(NR_CLOSE,(U)fd,0,0,0,0,0))fail(26,0);
 }
 for(U k=0;k<3;k++)if(!paths[k])fail(27,0);
}
static struct dm_ioctl *command(long fd,U role,const char*phase,U cmd,U flags,U size,long expected_rc){
 struct dm_ioctl*h=header(size);h->flags=(U32)flags;copy(h->name,names[role]);if(equal(phase,"create"))h->dev=role;
 if(equal(phase,"load")){
  h->target_count=1;struct dm_target_spec *v=(void*)(io+312);v->sector_start=0;v->length=16;v->status=0;v->next=0;copy(v->target_type,"verity");char *p=(void*)(io+352);p=copy(p,"1 ");p=copy(p,paths[role?2:0]);p=copy(p," ");p=copy(p,paths[1]);copy(p," 4096 4096 2 0 sha256 " ROOT_HEX " " SALT_HEX);
 }
 for(U i=0;i<size;i++)saved[i]=io[i];long rc=syscall6(NR_IOCTL,(U)fd,DM_IOCTL_CODE(cmd),(U)io,0,0,0);U bytes=h->data_size;if(bytes<305||bytes>size)fail(28,rc);
 begin("dm_ioctl");text(",\"role\":\"");text(role?"bad":"good");text("\",\"phase\":\"");text(phase);text("\",\"command\":");number(DM_IOCTL_CODE(cmd));text(",\"request_bytes\":");number(size);text(",\"request_hex\":\"");hex(saved,size);text("\",\"rc\":");signed_number(rc);text(",\"bytes\":");number(bytes);text(",\"raw_hex\":\"");hex(io,bytes);text("\"");finish();
 if(rc!=expected_rc)fail(29,rc);
 if(!rc&&!equal(phase,"remove")){
  if(h->version[0]!=4||h->version[1]!=50||h->version[2]||!equal(h->name,names[role]))fail(30,0);
  if(equal(phase,"create")){if(!h->dev||minor_number(h->dev)!=role)fail(31,0);mapdev[role]=h->dev;}
  else if(h->dev!=mapdev[role])fail(32,0);
  if((equal(phase,"resume")||equal(phase,"table")||equal(phase,"info"))&&((h->flags&99)!=33||h->target_count!=1))fail(33,0);
 }
 return h;
}
static long mapping(long fd,U role){
 command(fd,role,"create",DM_DEV_CREATE_CMD,9,312,0);command(fd,role,"load",DM_TABLE_LOAD_CMD,1,1024,0);command(fd,role,"resume",DM_DEV_SUSPEND_CMD,1,312,0);command(fd,role,"table",DM_TABLE_STATUS_CMD,17,1024,0);
 const char *path=role?"/dev/dm-1":"/dev/dm-0";long disk=syscall6(NR_OPENAT,(U)-100,(U)path,0x80000,0,0,0);if(disk<0)fail(34,disk);U64 size=0,rdev=inspect(disk,&size);if(size!=8192||rdev!=mapdev[role])fail(35,0);
 begin("mapped_device");text(",\"role\":\"");text(role?"bad":"good");text("\",\"path\":\"");text(path);text("\",\"bytes\":8192,\"readonly\":1,\"rdev\":");number((U)rdev);text(",\"stat_hex\":\"");hex(st,128);text("\"");finish();return disk;
}
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
 rc=syscall6(NR_MOUNT,(U)"devtmpfs",(U)"/dev",(U)"devtmpfs",10,(U)"mode=0755",0);if(rc)fail(16,rc);begin("devtmpfs");text(",\"rc\":0,\"flags\":10");finish();
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

 discover();copy(copy(names[0],"gv-good-"),nonce);copy(copy(names[1],"gv-bad-"),nonce);
 long good=mapping(fd,0);for(U k=0;k<2;k++){rc=syscall6(NR_PREAD64,(U)good,(U)(block+k*4096),4096,k*4096,0,0);if(rc!=4096)fail(36,rc);}for(U j=0;j<8192;j++)if(block[j]!=expected(j))fail(37,0);
 begin("good_read");text(",\"offset\":0,\"bytes\":8192,\"block_returns\":[4096,4096],\"raw_hex\":\"");hex(block,8192);text("\"");finish();command(fd,0,"info",DM_TABLE_STATUS_CMD,1,1024,0);
 long bad=mapping(fd,1);rc=syscall6(NR_PREAD64,(U)bad,(U)block,4096,4096,0,0);begin("bad_read");text(",\"offset\":4096,\"bytes\":4096,\"rc\":");signed_number(rc);finish();if(rc!=-5)fail(38,rc);command(fd,1,"info",DM_TABLE_STATUS_CMD,1,1024,0);
 if(syscall6(NR_CLOSE,(U)good,0,0,0,0,0)||syscall6(NR_CLOSE,(U)bad,0,0,0,0,0))fail(39,0);begin("mappings_closed");text(",\"good\":true,\"bad\":true");finish();
 command(fd,0,"remove",DM_DEV_REMOVE_CMD,0,312,0);command(fd,0,"gone",DM_DEV_STATUS_CMD,0,312,-6);command(fd,1,"remove",DM_DEV_REMOVE_CMD,0,312,0);command(fd,1,"gone",DM_DEV_STATUS_CMD,0,312,-6);
 rc=syscall6(NR_CLOSE,(U)fd,0,0,0,0,0);if(rc)fail(40,rc);rc=syscall6(NR_UMOUNT2,(U)"/dev",0,0,0,0,0);if(rc)fail(41,rc);
 begin("poweroff");text(",\"pid\":1,\"method\":\"LINUX_REBOOT_CMD_POWER_OFF\",\"dm_closed\":true,\"mappings_removed\":true,\"devtmpfs_unmounted\":true");finish();poweroff();fail(42,0);
}
__asm__(".global _start\n_start:\nmov x0,sp\nbl boot_entry\n1: b 1b\n");
